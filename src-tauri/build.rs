use std::fmt::Write as _;
use std::path::Path;

fn main() {
    // Listing any path below makes cargo rerun this script only for those paths, so everything
    // the build embeds must be listed, or a changed icon would silently keep the old one.
    for path in ["build.rs", "icons", "windows", "tauri.conf.json", "capabilities"] {
        println!("cargo:rerun-if-changed={path}");
    }

    let mut attributes = tauri_build::Attributes::new();
    // Release builds ask for administrator rights on launch, so VPN mode and the kill switch
    // always work. Debug builds don't: `tauri dev` can't start an exe that requires elevation.
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        attributes = attributes
            .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(include_str!("windows/admin.manifest")));
        if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
            // The exe runs as admin, often straight from Downloads. Load the DLLs it links to
            // from System32 only, so a planted version.dll or similar next to it is ignored.
            println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
        }
    }
    tauri_build::try_build(attributes).expect("failed to run tauri-build");

    if std::env::var_os("CARGO_FEATURE_EMBED_CORES").is_some() {
        embed_cores();
    }
}

/// Compresses everything in `core/` that the app runs or reads (exe, dll, dat) into OUT_DIR
/// and generates the table `cores.rs` includes, so a release is a single exe.
///
/// Every file must be listed with its SHA-256 in `core/SHA256SUMS` (committed to git), so a
/// core that changed without anyone deciding so fails the build instead of shipping.
fn embed_cores() {
    use sha2::{Digest, Sha256};

    println!("cargo:rerun-if-changed=core");
    let sums = std::fs::read_to_string("core/SHA256SUMS")
        .expect("embed-cores: core/SHA256SUMS is missing (see core/README.md)");
    let pinned: Vec<(String, String)> = sums
        .lines()
        .filter_map(|l| l.split_once(char::is_whitespace))
        .map(|(hash, name)| (hash.trim().to_ascii_lowercase(), name.trim().trim_start_matches('*').to_string()))
        .collect();
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let mut table = String::from("pub static FILES: &[EmbeddedFile] = &[\n");
    let mut names = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir("core").expect("core/ folder missing").flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
        if !matches!(ext.as_str(), "exe" | "dll" | "dat") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let data = std::fs::read(&path).unwrap();
        let hash = hex::encode(Sha256::digest(&data));
        match pinned.iter().find(|(_, n)| n.eq_ignore_ascii_case(&name)) {
            Some((expected, _)) if *expected == hash => {}
            Some((expected, _)) => panic!("embed-cores: core/{name} has SHA-256 {hash}, but SHA256SUMS pins {expected}"),
            None => panic!("embed-cores: core/{name} isn't listed in core/SHA256SUMS"),
        }
        let compressed = zstd::encode_all(&data[..], 12).expect("compressing a core failed");
        let packed = Path::new(&out_dir).join(format!("{name}.zst"));
        std::fs::write(&packed, compressed).unwrap();
        writeln!(
            table,
            "    EmbeddedFile {{ name: {name:?}, sha256: {hash:?}, data: include_bytes!({:?}) }},",
            packed.display().to_string()
        )
        .unwrap();
        names.push(name);
    }
    table.push_str("];\n");

    for required in ["xray.exe", "sing-box.exe"] {
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case(required)),
            "embed-cores: src-tauri/core/{required} is missing"
        );
    }
    std::fs::write(Path::new(&out_dir).join("embedded_cores.rs"), table).unwrap();
}
