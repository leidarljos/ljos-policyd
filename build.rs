//! ljos-policyd sits on phronesis (libphronesis, pkg-config name `phronesis`).
//!
//! Probe order: `PHRONESIS_DIR` (prefix with `lib/libphronesis.*`), then
//! `pkg-config phronesis`. A missing library is a build error.

fn main() {
    println!("cargo:rerun-if-env-changed=PHRONESIS_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    if let Ok(dir) = std::env::var("PHRONESIS_DIR") {
        let lib = std::path::Path::new(&dir).join("lib");
        println!("cargo:rustc-link-search=native={}", lib.display());
        println!("cargo:rustc-link-lib=phronesis");
        println!("cargo:rerun-if-changed={}", lib.display());
        return;
    }

    match pkg_config::Config::new().atleast_version("0.1").probe("phronesis") {
        Ok(_) => {}
        Err(e) => panic!(
            "ljos-policyd depends on phronesis (libphronesis). \
             Install it so `pkg-config --exists phronesis` succeeds, \
             or set PHRONESIS_DIR to a prefix that contains lib/libphronesis. \
             Source: https://github.com/leidarljos/phronesis ({e})"
        ),
    }
}
