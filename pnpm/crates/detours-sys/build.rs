//! Compile the vendored Detours sources for a Windows target. Other targets
//! build an empty crate.

fn main() {
    println!("cargo:rerun-if-changed=detours/src");
    if std::env::var_os("CARGO_CFG_TARGET_OS").is_none_or(|os| os != "windows") {
        return;
    }
    let mut build = cc::Build::new();
    build.cpp(true).cpp_link_stdlib(None);
    // The DLL that links this is loaded into arbitrary processes, which
    // have no MinGW C++ runtime to load, so it is linked statically.
    if std::env::var_os("CARGO_CFG_TARGET_ENV").is_some_and(|env| env == "gnu") {
        link_static_libstdcxx(&build);
    }
    build
        .include("detours/src")
        .define("WIN32_LEAN_AND_MEAN", "1")
        .define("_WIN32_WINNT", "0x0601")
        .warnings(false)
        .files(["detours.cpp", "modules.cpp", "disasm.cpp", "image.cpp", "creatwth.cpp"].map(
            |file| format!("detours/src/{file}"),
        ))
        .compile("detours");
}

fn link_static_libstdcxx(build: &cc::Build) {
    let output = build
        .get_compiler()
        .to_command()
        .arg("-print-file-name=libstdc++.a")
        .output()
        .expect("ask the C++ compiler for libstdc++.a");
    let library = std::path::PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let dir = library.parent().expect("libstdc++.a is in a directory");
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static=stdc++");
}
