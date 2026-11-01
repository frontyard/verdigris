fn main() {
    println!("cargo:rerun-if-env-changed=VERD_GIT_SHA");
}
