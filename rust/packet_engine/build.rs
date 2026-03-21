fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = format!("{}/target", crate_dir);

    let config = cbindgen::Config::from_file("cbindgen.toml").unwrap_or_default();

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(format!("{}/packet_engine.h", output_dir));
}
