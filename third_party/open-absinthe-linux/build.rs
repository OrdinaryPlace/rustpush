// unicorn-engine-sys bundles QEMU, which references 128-bit atomic intrinsics
// (`__atomic_*_16`). On Linux these live in libatomic, which is not linked by
// default; without this the test/bin link step fails with "undefined symbol:
// __atomic_compare_exchange_16" and friends.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-lib=atomic");
    }
}
