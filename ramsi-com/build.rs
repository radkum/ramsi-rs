fn main() {
    println!("cargo:rerun-if-changed=ramsi_com.def");
    let def =
        std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("ramsi_com.def");
    println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def.display());
}
