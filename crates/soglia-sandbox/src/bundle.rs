// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The OCI runtime configuration of one Execution.
//!
//! The agent runs as a configured non-root user with every capability set empty, `noNewPrivileges`,
//! a read-only root filesystem, size-limited tmpfs mounts, and a seccomp profile. It joins the
//! network namespace the enforcer already created and configured, by path, so the OCI runtime never
//! creates a network namespace of its own. It gets fresh PID, mount, IPC, UTS and cgroup namespaces.

use std::path::Path;

use serde_json::{Value, json};
use soglia_core::config::{AgentConfig, CpuMax};

/// `clone` flags that create namespaces. A `clone` asking for any of them is refused.
const CLONE_NAMESPACE_FLAGS: [u64; 7] = [
    0x0002_0000, // CLONE_NEWNS
    0x0200_0000, // CLONE_NEWCGROUP
    0x0400_0000, // CLONE_NEWUTS
    0x0800_0000, // CLONE_NEWIPC
    0x1000_0000, // CLONE_NEWUSER
    0x2000_0000, // CLONE_NEWPID
    0x4000_0000, // CLONE_NEWNET
];

/// Syscalls outside the Phase-0 sandbox surface. Each fails with `EPERM`.
const DENIED_SYSCALLS: [&str; 34] = [
    // Namespaces and mounts: the sandbox's shape is Soglia's, not the agent's.
    "unshare",
    "setns",
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "move_mount",
    "open_tree",
    "mount_setattr",
    // Kernel programmability and introspection.
    "bpf",
    "perf_event_open",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "userfaultfd",
    "keyctl",
    "add_key",
    "request_key",
    "open_by_handle_at",
    "name_to_handle_at",
    // Machine-level operations.
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "swapon",
    "swapoff",
    "acct",
    "quotactl",
];

/// io_uring is not needed in Phase 0, so it is excluded from the syscall surface.
const IO_URING_SYSCALLS: [&str; 3] = ["io_uring_setup", "io_uring_enter", "io_uring_register"];

const EPERM: u32 = 1;
const ENOSYS: u32 = 38;

/// Everything the configuration of one Execution depends on.
pub struct BundleInputs<'a> {
    /// The agent's configuration.
    pub agent: &'a AgentConfig,
    /// The network namespace the enforcer created for the Execution.
    pub netns_path: &'a Path,
    /// The Execution cgroup, relative to the cgroup v2 mount.
    pub cgroups_path: &'a str,
    /// Environment variables Soglia sets, which the agent's own cannot override.
    pub soglia_env: &'a [(String, String)],
}

/// The OCI `config.json` of one Execution.
pub fn config(inputs: &BundleInputs<'_>) -> Value {
    let agent = inputs.agent;
    let mut env: Vec<String> = Vec::new();
    if !agent.env.contains_key("PATH") {
        env.push("PATH=/usr/local/bin:/usr/bin:/bin".to_owned());
    }
    env.extend(
        agent
            .env
            .iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
    env.extend(
        inputs
            .soglia_env
            .iter()
            .map(|(key, value)| format!("{key}={value}")),
    );

    let mut mounts = vec![
        json!({"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]}),
        json!({"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}),
        json!({"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]}),
        json!({"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]}),
        json!({"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue", "options": ["nosuid", "noexec", "nodev"]}),
        json!({"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]}),
    ];
    for tmpfs in &agent.tmpfs {
        mounts.push(json!({
            "destination": tmpfs.path,
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "nodev", "noexec", "mode=1777", format!("size={}", tmpfs.size_bytes)],
        }));
    }

    let limits = &agent.limits;
    let mut resources = json!({
        "pids": { "limit": limits.pids_max },
        // Swap equal to the memory limit means no swap at all on cgroup v2.
        "memory": { "limit": limits.memory_max_bytes, "swap": limits.memory_max_bytes },
    });
    if let Some(CpuMax {
        quota_us,
        period_us,
    }) = limits.cpu_max
    {
        resources["cpu"] = json!({ "quota": quota_us, "period": period_us });
    }

    json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": { "uid": agent.uid, "gid": agent.gid },
            "args": agent.command,
            "env": env,
            "cwd": "/",
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": [],
            },
            "rlimits": [
                { "type": "RLIMIT_NOFILE", "hard": limits.nofile, "soft": limits.nofile },
                { "type": "RLIMIT_CORE", "hard": 0, "soft": 0 },
            ],
            "noNewPrivileges": true,
        },
        "root": { "path": agent.rootfs, "readonly": true },
        "hostname": "soglia",
        "mounts": mounts,
        "linux": {
            "namespaces": [
                { "type": "pid" },
                { "type": "network", "path": inputs.netns_path },
                { "type": "ipc" },
                { "type": "uts" },
                { "type": "mount" },
                { "type": "cgroup" },
            ],
            "cgroupsPath": inputs.cgroups_path,
            "resources": resources,
            "maskedPaths": [
                "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi",
                "/sys/firmware", "/sys/devices/virtual/powercap",
            ],
            "readonlyPaths": [
                "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
            ],
            "seccomp": seccomp(),
        },
    })
}

/// The Phase-0 seccomp profile: allow by default, refuse what the sandbox surface excludes.
pub fn seccomp() -> Value {
    let mut syscalls = vec![
        json!({ "names": &DENIED_SYSCALLS[..], "action": "SCMP_ACT_ERRNO", "errnoRet": EPERM }),
        json!({ "names": &IO_URING_SYSCALLS[..], "action": "SCMP_ACT_ERRNO", "errnoRet": EPERM }),
        // `clone3` passes its flags in memory, where the filter cannot read them, so it is refused
        // whole. `ENOSYS` makes C libraries fall back to `clone`, which the rules below can inspect.
        json!({ "names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": ENOSYS }),
    ];
    // Ordinary `clone`, `fork` and thread creation stay available; a `clone` that asks for any new
    // namespace does not.
    for flag in CLONE_NAMESPACE_FLAGS {
        syscalls.push(json!({
            "names": ["clone"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": EPERM,
            "args": [{ "index": 0, "value": flag, "valueTwo": flag, "op": "SCMP_CMP_MASKED_EQ" }],
        }));
    }

    json!({ "defaultAction": "SCMP_ACT_ALLOW", "syscalls": syscalls })
}

#[cfg(test)]
mod tests {
    use super::*;
    use soglia_core::config::Config;

    fn agent() -> AgentConfig {
        let config = Config::from_yaml(
            r#"
runtime: { uid: 990, gid: 990 }
agents:
  echo:
    rootfs: /var/lib/soglia/rootfs/echo
    command: ["/agent", "--serve"]
    env: { MODE: test }
"#,
        )
        .unwrap();
        config.agents["echo"].clone()
    }

    fn bundle() -> Value {
        let agent = agent();
        config(&BundleInputs {
            agent: &agent,
            netns_path: Path::new("/run/netns/soglia-0123456789"),
            cgroups_path: "/soglia/executions/0123456789",
            soglia_env: &[("HTTP_PROXY".into(), "http://10.200.255.1:15001".into())],
        })
    }

    #[test]
    fn the_agent_joins_the_soglia_network_namespace_by_path() {
        let bundle = bundle();
        let namespaces = bundle["linux"]["namespaces"].as_array().unwrap();
        let network: Vec<&Value> = namespaces
            .iter()
            .filter(|ns| ns["type"] == "network")
            .collect();
        assert_eq!(network.len(), 1);
        assert_eq!(network[0]["path"], "/run/netns/soglia-0123456789");
        for kind in ["pid", "ipc", "uts", "mount", "cgroup"] {
            assert!(
                namespaces
                    .iter()
                    .any(|ns| ns["type"] == kind && ns.get("path").is_none()),
                "{kind}"
            );
        }
        assert!(!namespaces.iter().any(|ns| ns["type"] == "user"));
    }

    #[test]
    fn the_agent_has_no_capabilities_and_no_new_privileges() {
        let process = &bundle()["process"];
        for set in [
            "bounding",
            "effective",
            "inheritable",
            "permitted",
            "ambient",
        ] {
            assert_eq!(process["capabilities"][set], json!([]), "{set}");
        }
        assert_eq!(process["noNewPrivileges"], true);
        assert_eq!(process["user"]["uid"], 65534);
        assert_eq!(process["terminal"], false);
    }

    #[test]
    fn the_root_is_read_only_and_only_tmpfs_is_writable() {
        let bundle = bundle();
        assert_eq!(bundle["root"]["readonly"], true);
        let tmp = bundle["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mount| mount["destination"] == "/tmp")
            .unwrap();
        assert_eq!(tmp["type"], "tmpfs");
        assert!(
            tmp["options"]
                .as_array()
                .unwrap()
                .contains(&json!("size=16777216"))
        );
    }

    #[test]
    fn limits_reach_the_cgroup() {
        let resources = &bundle()["linux"]["resources"];
        assert_eq!(resources["pids"]["limit"], 128);
        assert_eq!(resources["memory"]["limit"], 256 << 20);
        assert_eq!(resources["memory"]["swap"], 256 << 20);
        assert_eq!(resources["cpu"]["quota"], 100_000);
        assert_eq!(
            bundle()["linux"]["cgroupsPath"],
            "/soglia/executions/0123456789"
        );
    }

    #[test]
    fn soglia_variables_come_last_and_path_has_a_default() {
        let env = bundle()["process"]["env"].as_array().unwrap().clone();
        assert_eq!(env[0], "PATH=/usr/local/bin:/usr/bin:/bin");
        assert!(env.contains(&json!("MODE=test")));
        assert_eq!(env.last().unwrap(), "HTTP_PROXY=http://10.200.255.1:15001");
    }

    #[test]
    fn clone3_is_refused_whole_with_enosys() {
        let profile = seccomp();
        let rules = profile["syscalls"].as_array().unwrap();
        let clone3: Vec<&Value> = rules
            .iter()
            .filter(|rule| rule["names"].as_array().unwrap().contains(&json!("clone3")))
            .collect();
        assert_eq!(clone3.len(), 1);
        assert_eq!(clone3[0]["errnoRet"], 38);
        assert!(
            clone3[0].get("args").is_none(),
            "clone3 is refused without inspecting flags"
        );
    }

    #[test]
    fn io_uring_unshare_and_setns_are_refused() {
        let profile = seccomp();
        let denied: Vec<String> = profile["syscalls"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| rule["errnoRet"] == 1 && rule.get("args").is_none())
            .flat_map(|rule| {
                rule["names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|name| name.as_str().unwrap().to_owned())
            })
            .collect();
        for syscall in [
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            "unshare",
            "setns",
            "mount",
            "bpf",
        ] {
            assert!(denied.contains(&syscall.to_owned()), "{syscall}");
        }
    }

    #[test]
    fn a_namespace_creating_clone_is_refused_per_flag() {
        let profile = seccomp();
        let clone_rules: Vec<&Value> = profile["syscalls"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| rule["names"] == json!(["clone"]))
            .collect();
        assert_eq!(clone_rules.len(), CLONE_NAMESPACE_FLAGS.len());
        for rule in clone_rules {
            let condition = &rule["args"][0];
            assert_eq!(condition["op"], "SCMP_CMP_MASKED_EQ");
            assert_eq!(condition["value"], condition["valueTwo"]);
        }
    }
}
