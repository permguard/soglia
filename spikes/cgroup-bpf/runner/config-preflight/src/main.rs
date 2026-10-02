// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Validate generated qualification configurations with the production parser.

use std::env;
use std::fs;
use std::path::Path;

use soglia_core::Config;

fn validate(path: &Path) -> Result<(), String> {
    let yaml = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Config::from_yaml(&yaml)
        .map(|_| ())
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn run() -> Result<(), String> {
    let paths = env::args_os().skip(1).collect::<Vec<_>>();
    if paths.is_empty() {
        return Err("at least one generated configuration path is required".to_owned());
    }
    for path in paths {
        validate(Path::new(&path))?;
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("config-preflight: {error}");
        std::process::exit(13);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
runtime:
  uid: 990
  gid: 990
  state_dir: /run/soglia-preflight
  max_concurrency: 2
  max_queue: 2
network:
  backend: cgroup-bpf
  max_proxy_connections: 65
cgroup_bpf:
  max_tracked_sockets: 64
agents:
  echo:
    rootfs: /var/lib/soglia/rootfs/echo
    command: ["/agent"]
"#;

    #[test]
    fn production_parser_rejects_an_incoherent_qualification_envelope() {
        let error = Config::from_yaml(CONFIG).unwrap_err();
        assert!(error.to_string().contains(
            "network.max_proxy_connections must not exceed cgroup_bpf.max_tracked_sockets"
        ));
    }
}
