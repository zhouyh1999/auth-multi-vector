use std::path::PathBuf;

fn main() {
    let vendor = PathBuf::from("../gem-search/vendor/gem-otlib");
    for source in [
        "core.h",
        "full_bipartitegraph.h",
        "network_simplex_simple.h",
        "EMD.h",
        "gem_emd_shim.cpp",
    ] {
        println!("cargo:rerun-if-changed={}", vendor.join(source).display());
    }
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .warnings(false)
        .define("NDEBUG", None)
        .include(&vendor)
        .file(vendor.join("gem_emd_shim.cpp"))
        .compile("gem_qemd_lemon_v3");
}
