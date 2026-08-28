fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = format!("{}/target", crate_dir);

    // A parse failure must be fatal: the silent default config emits a C++
    // header, which breaks the Objective-C bridging header far from the cause.
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("failed to parse cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(format!("{}/packet_engine.h", output_dir));
}
