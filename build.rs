//! phronesis is a dependency (`phronesis-sys`), so every build of this
//! crate links it. The `has_phronesis` cfg stays set for the sources and
//! tests written while the library was optional.
fn main() {
    println!("cargo:rustc-check-cfg=cfg(has_phronesis)");
    println!("cargo:rustc-cfg=has_phronesis");
}
