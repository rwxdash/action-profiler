use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.join("../..");
    let bpf_src = manifest_dir.join("../profiler-ebpf");
    let libbpf_src = manifest_dir.join("../../libbpf/src");

    // Determine target architecture for BPF
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let bpf_arch = match arch.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => other,
    };

    let output = format!("{out_dir}/profiler.bpf.o");

    #[rustfmt::skip]
    let status = Command::new("clang")
        .args([
            "-target", "bpf", "-O2", "-g",
            &format!("-D__TARGET_ARCH_{bpf_arch}"),
            "-I", bpf_src.to_str().unwrap(),    // vmlinux.h
            "-I", libbpf_src.to_str().unwrap(), // bpf_helpers.h etc.
            "-c", bpf_src.join("profiler.bpf.c").to_str().unwrap(),
            "-o", &output,
        ])
        .status()
        .expect("clang is required to compile BPF programs");

    assert!(status.success(), "clang failed to compile BPF programs");

    // Rebuild if any BPF source file changes
    println!("cargo:rerun-if-changed={}", bpf_src.display());

    // Generate compile_commands.json for clangd
    let compile_commands = format!(
        r#"[
    {{
        "directory": "{}",
        "file": "profiler/profiler-ebpf/profiler.bpf.c",
        "command": "clang -xc -target bpf -std=gnu11 -D__TARGET_ARCH_{} -O2 -g -ferror-limit=0 -I {} -I {} -c {}"
    }}
]
"#,
        workspace_root.canonicalize().unwrap().display(),
        bpf_arch,
        bpf_src.canonicalize().unwrap().display(),
        libbpf_src.canonicalize().unwrap().display(),
        bpf_src
            .join("profiler.bpf.c")
            .canonicalize()
            .unwrap()
            .display(),
    );
    let cc_path = workspace_root.join("compile_commands.json");
    let _ = fs::write(&cc_path, compile_commands);
}
