// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/candidate_a.c");
    if env::var_os("CARGO_FEATURE_CGROUP_BPF").is_none() {
        return;
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let (target_arch, multiarch) = match arch.as_str() {
        "x86_64" => ("x86", "x86_64-linux-gnu"),
        "aarch64" => ("arm64", "aarch64-linux-gnu"),
        other => panic!("cgroup-bpf does not support target architecture {other}"),
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("soglia-cgroup-bpf.o");
    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            &format!("-D__TARGET_ARCH_{target_arch}"),
            &format!("-I/usr/include/{multiarch}"),
            "-c",
            "bpf/candidate_a.c",
            "-o",
        ])
        .arg(&out)
        .status()
        .unwrap_or_else(|error| panic!("cannot execute clang for cgroup-BPF: {error}"));
    assert!(
        status.success(),
        "clang could not build the production BPF object"
    );
}
