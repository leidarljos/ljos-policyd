//! Probe order: `PHRONESIS_DIR`, then `pkg-config phronesis`.
//! Missing library: compile the host argv table only (`has_phronesis` off).

fn link_prefix(dir: &str) {
    let lib = std::path::Path::new(dir).join("lib");
    let inc = std::path::Path::new(dir).join("include");
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib.display());
    println!("cargo:rustc-link-lib=phronesis");
    println!("cargo:rustc-link-lib=capnp_c");
    println!("cargo:rustc-link-lib=capnp_janet");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-cfg=has_phronesis");
    println!("cargo:rustc-env=PHRONESIS_PREFIX={dir}");
    println!("cargo:rerun-if-changed={}", lib.display());
    let mut cc = cc::Build::new();
    cc.file("src/native/shell_encode.c").include(&inc);
    let gen = std::path::Path::new(dir).join("share/phronesis/c");
    for name in ["policy.capnp.c", "util.capnp.c"] {
        let f = gen.join(name);
        if f.is_file() {
            cc.file(&f);
        }
    }
    cc.compile("ljos_shell_encode");
}

fn main() {
    println!("cargo:rerun-if-env-changed=PHRONESIS_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rustc-check-cfg=cfg(has_phronesis)");

    if let Ok(dir) = std::env::var("PHRONESIS_DIR") {
        link_prefix(&dir);
        return;
    }

    if pkg_config::Config::new()
        .atleast_version("0.1")
        .probe("phronesis")
        .is_ok()
    {
        println!("cargo:rustc-cfg=has_phronesis");
        return;
    }

    println!("cargo:warning=phronesis not found; building host argv table only");
}
