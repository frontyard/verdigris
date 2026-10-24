-- mem cell: random playlist across the channel set (sliding-window live
-- playlists are polled constantly by every viewer)
local channels = tonumber(os.getenv("M3U8_CHANNELS") or "100")
math.randomseed(math.floor((os.time() + os.clock()) * 1e6) % 2147483647)
request = function()
    return wrk.format("GET", string.format("/m3u8/ch%03d.m3u8", math.random(channels)))
end
