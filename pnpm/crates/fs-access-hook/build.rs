//! Detours adds the hook to a process's imports by ordinal 1, so the DLL
//! must export something there. It exports Detours' own
//! `DetourFinishHelperProcess`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=exports.def");
    if std::env::var_os("CARGO_CFG_TARGET_OS").is_none_or(|os| os != "windows") {
        return;
    }
    if std::env::var_os("CARGO_CFG_TARGET_ENV").is_some_and(|env| env == "msvc") {
        println!("cargo:rustc-cdylib-link-arg=/EXPORT:DetourFinishHelperProcess,@1,NONAME");
    } else {
        let def = std::path::Path::new(&std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .join("exports.def");
        println!("cargo:rustc-cdylib-link-arg={}", def.display());
    }
}
