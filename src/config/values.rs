//! Small value types used by the configuration model: [`ByteSize`] for
//! human sizes like `16KiB` and [`RateSpec`] for rates like `100/s`.

use std::fmt;
use std::time::Duration;

use schemars::JsonSchema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serde adapter for `BTreeMap<u16, V>`: TOML keys are strings, so keys
/// like `"404"` are parsed into `u16` status codes.
pub mod status_map {
    use std::collections::BTreeMap;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Deserialize string keys into `u16` HTTP status codes.
    pub fn deserialize<'de, D, V>(d: D) -> Result<BTreeMap<u16, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        BTreeMap::<String, V>::deserialize(d)?
            .into_iter()
            .map(|(k, v)| {
                k.parse::<u16>()
                    .map(|k| (k, v))
                    .map_err(|_| D::Error::custom(format!("invalid HTTP status code {k:?}")))
            })
            .collect()
    }

    /// Serialize status codes back to string keys.
    pub fn serialize<S, V>(m: &BTreeMap<u16, V>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        m.iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<BTreeMap<_, _>>()
            .serialize(s)
    }
}

/// Serde adapter for `Vec<T>` fields: `x = "v"` parses as `["v"]` —
/// scalar sugar for the common single-entry case (see
/// `docs/config-grammar.md`; `include` deliberately stays strict).
/// Serializes as the list form — canonical output is always an array.
pub mod one_or_many {
    use serde::{Deserialize, Deserializer};

    /// Deserialize `v` or `[v, …]` into `Vec<T>`.
    ///
    /// `Many` is tried first: an untagged `One(T)` where `T` is a
    /// struct-with-defaults would positionally accept `[]` and produce
    /// a bogus single element.
    pub fn deserialize<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr<T> {
            Many(Vec<T>),
            One(T),
        }
        match Repr::deserialize(d)? {
            Repr::Many(v) => Ok(v),
            Repr::One(v) => Ok(vec![v]),
        }
    }
}

/// Serde adapter for `Vec<IpNet>`/`Option<Vec<IpNet>>` fields: the
/// same scalar-or-list sugar as `one_or_many`, plus bare IPs — a
/// `"10.0.0.1"` entry parses as the host route `10.0.0.1/32` (and
/// `::1` as `/128`), since a prefix is almost never what an operator
/// means to omit.
pub mod cidr {
    use std::net::IpAddr;

    use ipnet::IpNet;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    /// Parse a CIDR or a bare IP (interpreted as a host route).
    pub fn parse(s: &str) -> Result<IpNet, String> {
        s.parse::<IpNet>().or_else(|_| {
            s.parse::<IpAddr>()
                .map(|ip| match ip {
                    IpAddr::V4(a) => IpNet::V4(ipnet::Ipv4Net::from(a)),
                    IpAddr::V6(a) => IpNet::V6(ipnet::Ipv6Net::from(a)),
                })
                .map_err(|_| {
                    format!("invalid network {s:?} — expected a CIDR (\"10.0.0.0/8\") or IP (\"10.0.0.1\")")
                })
        })
    }

    /// Deserialize `v` or `[v, …]` into `Vec<IpNet>`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<IpNet>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Many(Vec<String>),
            One(String),
        }
        let raw = match Repr::deserialize(d)? {
            Repr::Many(v) => v,
            Repr::One(s) => vec![s],
        };
        raw.iter()
            .map(|s| parse(s).map_err(Error::custom))
            .collect()
    }

    /// Same sugar for `Option<Vec<IpNet>>` fields.
    pub mod option {
        use ipnet::IpNet;
        use serde::de::Error;
        use serde::{Deserialize, Deserializer};

        /// Deserialize `v`, `[v, …]`, or none into `Option<Vec<IpNet>>`.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<Vec<IpNet>>, D::Error> {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum Repr {
                Many(Vec<String>),
                One(String),
            }
            Option::<Repr>::deserialize(d)?
                .map(|r| match r {
                    Repr::Many(v) => v,
                    Repr::One(s) => vec![s],
                })
                .map(|v| {
                    v.iter()
                        .map(|s| super::parse(s).map_err(Error::custom))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
        }
    }
}

/// Canonical short form for a [`Duration`]: the largest unit that
/// divides it evenly (`"180d"`, `"2h"`, `"90s"`), falling back to
/// humantime's compound form when no single unit is exact. Used when
/// serializing durations back out (`verd config`, schema defaults).
pub fn format_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    const UNITS: [(u128, &str); 7] = [
        (86_400_000_000_000, "d"),
        (3_600_000_000_000, "h"),
        (60_000_000_000, "m"),
        (1_000_000_000, "s"),
        (1_000_000, "ms"),
        (1_000, "us"),
        (1, "ns"),
    ];
    for (unit_ns, suffix) in UNITS {
        if ns >= unit_ns && ns.is_multiple_of(unit_ns) {
            return format!("{}{}", ns / unit_ns, suffix);
        }
    }
    humantime::format_duration(d).to_string()
}

/// Serde adapter for [`Duration`] fields: humantime strings only
/// (`"30s"`, `"180d"`). Serializes as the compact canonical string.
pub mod duration {
    use std::time::Duration;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Deserialize a humantime string like `"180d"`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        humantime::parse_duration(&s).map_err(Error::custom)
    }

    /// Serialize as `"180d"`.
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::format_duration(*d))
    }

    /// Same for `Option<Duration>` fields.
    pub mod option {
        use std::time::Duration;

        use serde::de::Error;
        use serde::{Deserialize, Deserializer, Serializer};

        /// Deserialize `null` or a humantime string.
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
            Option::<String>::deserialize(d)?
                .map(|s| humantime::parse_duration(&s).map_err(Error::custom))
                .transpose()
        }

        /// Serialize `null` or `"180d"`.
        pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
            match d {
                Some(d) => s.serialize_str(&super::super::format_duration(*d)),
                None => s.serialize_none(),
            }
        }
    }
}

/// A byte size parsed from `123`, `"123B"`, `"16KiB"`, `"10MB"`, `"4GiB"`.
/// Unit-less strings and integers mean bytes. `K`/`M`/`G` suffixes are
/// decimal (×1000); `Ki`/`Mi`/`Gi` are binary (×1024).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// Construct a size in bytes.
    pub const fn bytes(n: u64) -> Self {
        Self(n)
    }
    /// Construct a size in kibibytes.
    pub const fn kib(n: u64) -> Self {
        Self(n * 1024)
    }
    /// Construct a size in mebibytes.
    pub const fn mib(n: u64) -> Self {
        Self(n * 1024 * 1024)
    }
    /// Construct a size in gibibytes.
    pub const fn gib(n: u64) -> Self {
        Self(n * 1024 * 1024 * 1024)
    }

    /// Parse a human size string.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Ok(n) = s.parse::<u64>() {
            return Ok(Self(n));
        }
        let split = s
            .find(|c: char| c.is_ascii_alphabetic())
            .ok_or_else(|| format!("invalid byte size {s:?}"))?;
        let (num, unit) = s.split_at(split);
        let num: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid byte size {s:?}"))?;
        let factor: u64 = match unit.trim().to_ascii_lowercase().as_str() {
            "b" => 1,
            "k" | "kb" => 1000,
            "m" | "mb" => 1000 * 1000,
            "g" | "gb" => 1000 * 1000 * 1000,
            "t" | "tb" => 1000 * 1000 * 1000 * 1000,
            "kib" => 1024,
            "mib" => 1024 * 1024,
            "gib" => 1024 * 1024 * 1024,
            "tib" => 1024 * 1024 * 1024 * 1024,
            _ => return Err(format!("invalid byte size unit in {s:?}")),
        };
        Ok(Self((num * factor as f64) as u64))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KIB: u64 = 1024;
        const MIB: u64 = KIB * 1024;
        const GIB: u64 = MIB * 1024;
        if self.0.is_multiple_of(GIB) && self.0 >= GIB {
            write!(f, "{}GiB", self.0 / GIB)
        } else if self.0.is_multiple_of(MIB) && self.0 >= MIB {
            write!(f, "{}MiB", self.0 / MIB)
        } else if self.0.is_multiple_of(KIB) && self.0 >= KIB {
            write!(f, "{}KiB", self.0 / KIB)
        } else {
            write!(f, "{}B", self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Int(u64),
            Str(String),
        }
        match Repr::deserialize(d)? {
            Repr::Int(n) => Ok(Self(n)),
            Repr::Str(s) => Self::parse(&s).map_err(D::Error::custom),
        }
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// A rate like `100/s`, `600/m`, `10000/h`, `50000/day`, or `10/30s`
/// for arbitrary periods. Units: `s`, `m`, `h`, `d` or the words
/// `second`, `minute`, `hour`, `day` (also plural), or a humantime
/// duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema)]
pub struct RateSpec {
    /// Number of permits granted per `period`.
    pub permits: u64,
    /// Length of one period.
    pub period: Duration,
}

impl RateSpec {
    /// Tokens granted per second, as a float.
    pub fn per_second(&self) -> f64 {
        self.permits as f64 / self.period.as_secs_f64()
    }

    /// Parse a rate string.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (num, unit) = s
            .split_once('/')
            .ok_or_else(|| format!("invalid rate {s:?}, expected e.g. \"100/s\""))?;
        let permits: u64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid rate count in {s:?}"))?;
        let period = match unit.trim().to_ascii_lowercase().as_str() {
            "s" | "sec" | "second" | "seconds" => Duration::from_secs(1),
            "m" | "min" | "minute" | "minutes" => Duration::from_secs(60),
            "h" | "hr" | "hour" | "hours" => Duration::from_secs(3600),
            "d" | "day" | "days" => Duration::from_secs(86400),
            other => humantime::parse_duration(other)
                .map_err(|_| format!("invalid rate unit in {s:?}"))?,
        };
        Ok(Self { permits, period })
    }
}

impl fmt::Display for RateSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unit = match self.period.as_secs() {
            1 => "s",
            60 => "m",
            3600 => "h",
            86400 => "d",
            secs => return write!(f, "{}/{}s", self.permits, secs),
        };
        write!(f, "{}/{}", self.permits, unit)
    }
}

impl<'de> Deserialize<'de> for RateSpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(D::Error::custom)
    }
}

impl Serialize for RateSpec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_size_parses_units() {
        assert_eq!(ByteSize::parse("1024").unwrap().0, 1024);
        assert_eq!(ByteSize::parse("1KiB").unwrap().0, 1024);
        assert_eq!(ByteSize::parse("16KiB").unwrap().0, 16 * 1024);
        assert_eq!(ByteSize::parse("1MB").unwrap().0, 1_000_000);
        assert_eq!(ByteSize::parse("1.5GiB").unwrap().0, 1610612736);
        assert!(ByteSize::parse("banana").is_err());
    }

    #[test]
    fn byte_size_displays() {
        assert_eq!(ByteSize::kib(16).to_string(), "16KiB");
        assert_eq!(ByteSize::bytes(100).to_string(), "100B");
    }

    #[test]
    fn rate_spec_parses() {
        let r = RateSpec::parse("100/s").unwrap();
        assert_eq!(r.permits, 100);
        assert_eq!(r.period, Duration::from_secs(1));
        let r = RateSpec::parse("600/minute").unwrap();
        assert_eq!(r.period, Duration::from_secs(60));
        assert!((r.per_second() - 10.0).abs() < 1e-9);
        assert!(RateSpec::parse("100").is_err());
        assert!(RateSpec::parse("x/s").is_err());
    }

    #[test]
    fn byte_size_remaining_units_and_errors() {
        assert_eq!(ByteSize::parse("2T").unwrap().0, 2_000_000_000_000);
        assert_eq!(ByteSize::parse("2TiB").unwrap().0, 2 * 1024_u64.pow(4));
        assert_eq!(ByteSize::parse("1K").unwrap().0, 1000);
        assert_eq!(ByteSize::parse("2 G").unwrap().0, 2_000_000_000);
        assert!(ByteSize::parse("1PB").is_err());
        assert!(ByteSize::parse("xB").is_err());
        // serde paths: integer and string forms, plus a deserialize error
        assert_eq!(
            toml::from_str::<ByteSizeHolder>("v = 4096").unwrap().v.0,
            4096
        );
        assert!(toml::from_str::<ByteSizeHolder>("v = \"bogus\"").is_err());
        // Serialize round-trips through Display
        let mut out = String::new();
        serde::Serialize::serialize(&ByteSize::mib(1), toml::ser::ValueSerializer::new(&mut out))
            .unwrap();
        assert_eq!(out, "\"1MiB\"");
    }

    #[derive(serde::Deserialize)]
    struct ByteSizeHolder {
        v: ByteSize,
    }

    #[test]
    fn byte_size_display_all_brackets() {
        assert_eq!(ByteSize::gib(4).to_string(), "4GiB");
        assert_eq!(ByteSize::mib(10).to_string(), "10MiB");
        assert_eq!(ByteSize::kib(16).to_string(), "16KiB");
        assert_eq!(ByteSize::bytes(513).to_string(), "513B");
        // not an exact multiple falls through to bytes
        assert_eq!(ByteSize::bytes(1025).to_string(), "1025B");
    }

    #[test]
    fn rate_spec_all_units_and_display() {
        assert_eq!(RateSpec::parse("1/sec").unwrap().period.as_secs(), 1);
        assert_eq!(RateSpec::parse("1/hour").unwrap().period.as_secs(), 3600);
        assert_eq!(RateSpec::parse("5/day").unwrap().period.as_secs(), 86400);
        assert!(RateSpec::parse("1/fortnight").is_err());
        // Display: each canonical unit plus the seconds fallback
        assert_eq!(RateSpec::parse("100/s").unwrap().to_string(), "100/s");
        assert_eq!(RateSpec::parse("5/m").unwrap().to_string(), "5/m");
        assert_eq!(RateSpec::parse("5/h").unwrap().to_string(), "5/h");
        assert_eq!(RateSpec::parse("5/d").unwrap().to_string(), "5/d");
        let odd = RateSpec {
            permits: 7,
            period: Duration::from_secs(90),
        };
        assert_eq!(odd.to_string(), "7/90s");
        let mut out = String::new();
        serde::Serialize::serialize(
            &RateSpec::parse("1/s").unwrap(),
            toml::ser::ValueSerializer::new(&mut out),
        )
        .unwrap();
        assert_eq!(out, "\"1/s\"");
        assert!(toml::from_str::<RateHolder>("r = \"nope\"").is_err());
    }

    #[derive(serde::Deserialize)]
    struct RateHolder {
        #[allow(dead_code)]
        r: RateSpec,
    }

    #[test]
    fn status_map_keys_are_statuses() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        #[derive(serde::Deserialize)]
        struct Wrap {
            #[serde(with = "status_map")]
            m: BTreeMap<u16, PathBuf>,
        }
        let w: Wrap = toml::from_str("m = { \"404\" = \"/404.html\" }").unwrap();
        assert_eq!(w.m[&404], PathBuf::from("/404.html"));
        assert!(toml::from_str::<Wrap>("m = { \"oops\" = \"/x\" }").is_err());
    }
}
