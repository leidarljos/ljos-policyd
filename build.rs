//! Probe order: `PHRONESIS_DIR`, then `pkg-config phronesis`.
//! Missing library: compile the host argv table only (`has_phronesis` off).
//!
//! A phronesis build links libphronesis and the Cap'n Proto C runtime it
//! needs as static archives, and embeds the installed default pack, so the
//! binary runs on a host with no phronesis install and records no path from
//! the machine that built it.

use std::path::{Path, PathBuf};

/// Static archives a phronesis build links, in link order.
const STATIC_LIBS: &[&str] = &["phronesis", "capnp_janet", "capnp_c"];

/// The library directory under `prefix` holding `libphronesis.a`: `lib`,
/// `lib64`, or a Debian multiarch directory such as `lib/x86_64-linux-gnu`.
fn find_libdir(prefix: &Path) -> Option<PathBuf> {
    let mut cands = vec![prefix.join("lib"), prefix.join("lib64")];
    if let Some(triple) = multiarch() {
        cands.push(prefix.join("lib").join(triple));
    }
    if let Ok(rd) = std::fs::read_dir(prefix.join("lib")) {
        let mut more: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        more.sort();
        cands.extend(more);
    }
    cands
        .into_iter()
        .find(|d| d.join("libphronesis.a").is_file())
}

/// Debian's multiarch name for the target, from Cargo's `TARGET`.
fn multiarch() -> Option<String> {
    let target = std::env::var("TARGET").ok()?;
    let arch = target.split('-').next()?;
    if !target.contains("linux") {
        return None;
    }
    let abi = if target.ends_with("musl") {
        "musl"
    } else {
        "gnu"
    };
    let arch = match arch {
        "armv7" => "arm",
        a => a,
    };
    let suffix = if arch == "arm" { "gnueabihf" } else { abi };
    Some(format!("{arch}-linux-{suffix}"))
}

fn link_static(libdir: &Path) {
    println!("cargo:rustc-link-search=native={}", libdir.display());
    for lib in STATIC_LIBS {
        println!("cargo:rustc-link-lib=static={lib}");
    }
    for lib in ["dl", "m", "pthread"] {
        println!("cargo:rustc-link-lib={lib}");
    }
    println!(
        "cargo:rerun-if-changed={}",
        libdir.join("libphronesis.a").display()
    );
}

/// Compile the ShellCheck shim with the schema C the library was built with.
fn compile_shim(includes: &[PathBuf], cdir: &Path) {
    let mut cc = cc::Build::new();
    cc.file("src/native/shell_encode.c").include(cdir);
    for inc in includes {
        cc.include(inc);
    }
    for name in ["policy.capnp.c", "util.capnp.c"] {
        let f = cdir.join(name);
        if !f.is_file() {
            panic!(
                "phronesis: {} missing; install phronesis 0.2 or later",
                f.display()
            );
        }
        cc.file(&f);
    }
    cc.compile("ljos_shell_encode");
}

/// Copy the installed pack (`shell.janet`, `seat.janet`, `lib/*.janet`)
/// into OUT_DIR and write `pack.rs`, a table of embedded files.
fn embed_pack(packdir: &Path) {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dst = out.join("pack");
    let _ = std::fs::remove_dir_all(&dst);
    std::fs::create_dir_all(dst.join("lib")).unwrap();
    let mut files: Vec<String> = Vec::new();
    for entry in ["shell.janet", "seat.janet"] {
        let src = packdir.join(entry);
        if src.is_file() {
            std::fs::copy(&src, dst.join(entry)).unwrap();
            files.push(entry.to_string());
        }
    }
    if !files.iter().any(|f| f == "shell.janet") {
        panic!("phronesis: {}/shell.janet missing", packdir.display());
    }
    let mut libs: Vec<PathBuf> = std::fs::read_dir(packdir.join("lib"))
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    libs.retain(|p| p.extension().is_some_and(|e| e == "janet"));
    libs.sort();
    for p in libs {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        std::fs::copy(&p, dst.join("lib").join(&name)).unwrap();
        files.push(format!("lib/{name}"));
    }
    let mut rs = String::from("pub(crate) const PACK: &[(&str, &[u8])] = &[\n");
    for f in &files {
        rs.push_str(&format!(
            "    ({f:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/pack/{f}\"))),\n"
        ));
    }
    rs.push_str("];\n");
    std::fs::write(out.join("pack.rs"), rs).unwrap();
    println!("cargo:rerun-if-changed={}", packdir.display());
}

fn from_prefix(dir: &Path) -> bool {
    let Some(libdir) = find_libdir(dir) else {
        println!(
            "cargo:warning=PHRONESIS_DIR={}: no libphronesis.a under lib, lib64 or lib/<multiarch>",
            dir.display()
        );
        return false;
    };
    // The shim first: a static archive resolves only against archives
    // after it on the link line.
    compile_shim(&[dir.join("include")], &dir.join("share/phronesis/c"));
    link_static(&libdir);
    embed_pack(&dir.join("share/phronesis/policy"));
    true
}

fn from_pkg_config() -> bool {
    let Ok(lib) = pkg_config::Config::new()
        .atleast_version("0.2")
        .statik(true)
        .cargo_metadata(false)
        .probe("phronesis")
    else {
        return false;
    };
    let var = |name: &str| pkg_config::get_variable("phronesis", name).ok();
    let Some(libdir) = lib
        .link_paths
        .iter()
        .find(|d| d.join("libphronesis.a").is_file())
    else {
        println!("cargo:warning=pkg-config phronesis: no libphronesis.a on its link path");
        return false;
    };
    let prefix = var("prefix").map(PathBuf::from);
    let cdir = var("cdir")
        .map(PathBuf::from)
        .or_else(|| prefix.as_ref().map(|p| p.join("share/phronesis/c")))
        .expect("pkg-config phronesis: no cdir or prefix");
    let packdir = var("packdir")
        .map(PathBuf::from)
        .or_else(|| prefix.as_ref().map(|p| p.join("share/phronesis/policy")))
        .expect("pkg-config phronesis: no packdir or prefix");
    compile_shim(&lib.include_paths, &cdir);
    link_static(libdir);
    embed_pack(&packdir);
    true
}

fn main() {
    println!("cargo:rerun-if-env-changed=PHRONESIS_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rustc-check-cfg=cfg(has_phronesis)");

    let found = match std::env::var_os("PHRONESIS_DIR") {
        Some(dir) => from_prefix(Path::new(&dir)),
        None => from_pkg_config(),
    };
    if found {
        println!("cargo:rustc-cfg=has_phronesis");
    } else {
        println!("cargo:warning=phronesis not found; building host argv table only");
    }
}
