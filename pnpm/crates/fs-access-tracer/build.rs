//! On macOS and Windows, pnpm records file accesses from inside the
//! recorded processes, through `pnpm-fs-access-hook`. This builds that
//! library for the target and embeds it; on macOS it also embeds the shell
//! and core utilities that stand in for the system's, whose binaries macOS
//! will not load a library into.
//!
//! `PNPM_FS_ACCESS_ARTIFACTS` names a directory holding the artifacts
//! already built, which is used instead: for checking a target this host
//! cannot link for, or for a build without network access.

use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PNPM_FS_ACCESS_ARTIFACTS");
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let hook_name = match os.as_str() {
        "windows" => "pnpm_fs_access_hook.dll",
        "macos" => "libpnpm_fs_access_hook.dylib",
        _ => return,
    };
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let prebuilt = env::var_os("PNPM_FS_ACCESS_ARTIFACTS").map(PathBuf::from);
    let hook = match &prebuilt {
        Some(dir) => dir.join(hook_name),
        None => build_hook(&out_dir, hook_name),
    };
    embed("HOOK", &hook);
    if os == "macos" {
        for (name, download) in macos::downloads() {
            let path = match &prebuilt {
                Some(dir) => dir.join(name),
                None => macos::fetch(&out_dir, name, &download),
            };
            embed(&name.to_uppercase(), &path);
        }
    }
}

/// Tell the crate where the artifact is and what its contents hash to.
fn embed(name: &str, path: &Path) {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    println!("cargo:rerun-if-changed={}", path.display());
    println!("cargo:rustc-env=PNPM_FS_ACCESS_{name}_PATH={}", path.display());
    println!("cargo:rustc-env=PNPM_FS_ACCESS_{name}_HASH={}", hex(&Sha256::digest(&bytes)[..8]));
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Build the hook library for this build's target, in a target directory
/// of its own so the build does not wait on the one running this script.
fn build_hook(out_dir: &Path, hook_name: &str) -> PathBuf {
    let crates = Path::new(&env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets it")).join("..");
    for dependency in ["fs-access-hook", "fs-access-protocol", "detours-sys"] {
        println!("cargo:rerun-if-changed={}", crates.join(dependency).display());
    }
    let target = env::var("TARGET").expect("cargo sets TARGET");
    let release = env::var("PROFILE").is_ok_and(|profile| profile == "release");
    let target_dir = out_dir.join("hook");
    let status = Command::new(env::var_os("CARGO").expect("cargo sets CARGO"))
        .arg("build")
        .arg("--manifest-path")
        .arg(crates.join("fs-access-hook/Cargo.toml"))
        .args(["--lib", "--target", &target, "--target-dir"])
        .arg(&target_dir)
        .args(release.then_some("--release"))
        // The hook is loaded into other programs: build it as itself, not
        // with the wrappers and flags of whatever command runs this build
        // (clippy, coverage instrumentation).
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CLIPPY_ARGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR")
        .status()
        .expect("run cargo to build pnpm-fs-access-hook");
    assert!(status.success(), "building pnpm-fs-access-hook failed");
    target_dir
        .join(&target)
        .join(if release { "release" } else { "debug" })
        .join(hook_name)
}

mod macos {
    use super::{Path, PathBuf, Read, fs, hex};
    use sha2::{Digest, Sha256};
    use std::process::Command;

    pub(super) struct Download {
        url: String,
        path_in_archive: String,
        sha256: &'static str,
    }

    /// The POSIX shell ([Oils](https://oils.pub)) and the core utilities
    /// ([uutils](https://github.com/uutils/coreutils)) for this target,
    /// pinned by the SHA-256 of the extracted binary. The Oils builds are
    /// the ones Vite+ ships (<https://github.com/wan9chi/oils-for-unix-build>).
    pub(super) fn downloads() -> [(&'static str, Download); 2] {
        let arm = std::env::var("CARGO_CFG_TARGET_ARCH").is_ok_and(|arch| arch == "aarch64");
        let (oils_arch, oils_sha256, uutils_triple, uutils_sha256) = if arm {
            (
                "arm64",
                "b6e9d77aa6b22692f6132ca03346a8e166f1f57d966712f0ffff14c89412df15",
                "aarch64-apple-darwin",
                "8e8f38d9323135a19a73d617336fce85380f3c46fcb83d3ae3e031d1c0372f21",
            )
        } else {
            (
                "x86_64",
                "1a41a729538fd3663809c70f72179503345ea717b956607771ba766574ab6382",
                "x86_64-apple-darwin",
                "6be8bee6e8b91fc44a465203b9cc30538af00084b6657dc136d9e55837753eb1",
            )
        };
        let oils_url = format!(
            "https://github.com/wan9chi/oils-for-unix-build/releases/download/oils-for-unix-0.38.0/oils-for-unix-0.38.0-darwin-{oils_arch}.tar.gz"
        );
        let uutils_url = format!(
            "https://github.com/uutils/coreutils/releases/download/0.4.0/coreutils-0.4.0-{uutils_triple}.tar.gz"
        );
        let uutils_path = format!("coreutils-0.4.0-{uutils_triple}/coreutils");
        [
            (
                "shell",
                Download {
                    url: oils_url,
                    path_in_archive: "oils-for-unix".to_string(),
                    sha256: oils_sha256,
                },
            ),
            (
                "coreutils",
                Download { url: uutils_url, path_in_archive: uutils_path, sha256: uutils_sha256 },
            ),
        ]
    }

    /// The binary, downloaded and checked, or the copy a previous build
    /// left in `out_dir` when its hash still matches.
    pub(super) fn fetch(out_dir: &Path, name: &str, download: &Download) -> PathBuf {
        let path = out_dir.join(name);
        let cached = fs::read(&path).is_ok_and(|bytes| sha256(&bytes) == download.sha256);
        if cached {
            return path;
        }
        let output = Command::new("curl")
            .args(["--fail", "--location", "--silent", "--show-error", &download.url])
            .output()
            .unwrap_or_else(|error| panic!("run curl for {}: {error}", download.url));
        assert!(output.status.success(), "downloading {} failed", download.url);
        let binary = extract(&output.stdout, &download.path_in_archive);
        assert_eq!(
            sha256(&binary),
            download.sha256,
            "{} in {} does not have the pinned SHA-256",
            download.path_in_archive,
            download.url,
        );
        fs::write(&path, binary).expect("write the downloaded binary");
        path
    }

    fn extract(tarball: &[u8], wanted: &str) -> Vec<u8> {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tarball));
        for entry in archive.entries().expect("read the archive") {
            let mut entry = entry.expect("read an archive entry");
            if entry
                .path()
                .is_ok_and(|path| path == Path::new(wanted))
            {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).expect("extract the binary");
                return bytes;
            }
        }
        panic!("{wanted} is not in the archive");
    }

    fn sha256(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }
}
