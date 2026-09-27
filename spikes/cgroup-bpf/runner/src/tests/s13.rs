// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::command::{CommandExecutor, CommandOutput, CommandSpec, RunningCommand};
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::s1::{S1, inode, json_cgroup, json_command, wait_for_path};
use crate::tests::{SpikeTest, TestError};

const MAGIC: &str = "SOGLIA_CGROUP_BPF_SPIKE_STATE";
const SCHEMA: u64 = 1;
const ABI: u64 = 1;
const MAPS: [&str; 10] = [
    "soglia_policy",
    "soglia_tuples",
    "soglia_cookie_a",
    "soglia_sk_b",
    "soglia_events",
    "soglia_counters",
    "soglia_denies",
    "soglia_meta",
    "soglia_diag_entries",
    "soglia_port_diag",
];
const LINKS: [&str; 6] = [
    "sock_create",
    "connect4",
    "connect6",
    "sendmsg4",
    "sendmsg6",
    "sock_ops",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateRecord {
    magic: String,
    schema_version: u64,
    abi_version: u64,
    state_id: String,
    generation: u64,
    phase: String,
    pin_root: String,
    object_sha256: String,
    cgroup_path: String,
    cgroup_inode: u64,
    map_ids: Value,
    programs: Value,
    links: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Classification {
    Fresh,
    KnownCompatible,
    Incompatible,
    Unknown,
}

#[derive(Debug)]
struct ManagerFailure {
    classification: Classification,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StartOutcome {
    classification: Classification,
    old_generation: Option<u64>,
    swept: bool,
    record: StateRecord,
    ready_published: bool,
    ordering: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompatibleCase {
    old_record: StateRecord,
    new_record: StateRecord,
    old_map_ids: Value,
    new_map_ids: Value,
    old_policy: Value,
    old_cookie: Value,
    old_tuple: Value,
    new_policy: Value,
    new_cookie: Value,
    new_tuple: Value,
    old_tuple_lookup_after_recovery: bool,
    old_kernel_ids_absent: bool,
    ready_after_recovery: bool,
    ordering: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefusalCase {
    classification: Classification,
    detail: String,
    ready: bool,
    ids_before: Value,
    ids_after: Value,
    content_before: Value,
    content_after: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CrashCase {
    fault: String,
    ready_at_fault: bool,
    record_at_fault: StateRecord,
    recovery: StartOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S13Observation {
    contract: Value,
    original_historical_failure_preserved: bool,
    baseline_programs: Value,
    baseline_links: Value,
    baseline_maps: Value,
    compatible: CompatibleCase,
    incompatible: RefusalCase,
    unknown: RefusalCase,
    stale_generation_authorized_new: bool,
    crash_cases: Vec<CrashCase>,
    broad_name_cleanup_used: bool,
    production_backend_implemented: bool,
}

pub struct S13 {
    fixture: S1,
    pin_root: PathBuf,
    record_dir: PathBuf,
    record_path: PathBuf,
    ready: PathBuf,
    cgroups: Vec<PathBuf>,
    baseline: Option<(Value, Value, Value)>,
    created_trust_anchor: bool,
}

impl S13 {
    pub fn new(context: &TestContext) -> Self {
        let suffix = context.run_id.replace('-', "");
        let pin_root = Path::new("/sys/fs/bpf/soglia-spike-runner")
            .join(&context.run_id)
            .join("s13-managed");
        let record_dir = Path::new("/run/soglia").join(format!("cgroup-bpf-spike-{suffix}"));
        Self {
            fixture: S1::new_s13(context),
            pin_root,
            record_path: record_dir.join("state.json"),
            record_dir,
            ready: Path::new("/run/soglia-spike-runner")
                .join(&context.run_id)
                .join("s13-managed.ready"),
            cgroups: Vec::new(),
            baseline: None,
            created_trust_anchor: false,
        }
    }

    fn commands(&self, context: &TestContext) -> CommandExecutor {
        self.fixture.commands(context)
    }

    fn object<'a>(&self, context: &'a TestContext) -> PathBuf {
        context.artifact("bpf/soglia-diag.o")
    }

    fn object_hash(&self, context: &TestContext) -> Result<String, TestError> {
        let bytes = fs::read(self.object(context))
            .map_err(|error| TestError::infra(format!("read S13 object: {error}")))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn create_case_cgroup(
        &mut self,
        context: &mut TestContext,
        name: &str,
    ) -> Result<PathBuf, TestError> {
        let path = self
            .fixture
            .executions
            .as_ref()
            .ok_or_else(|| TestError::infra("S13 executions cgroup missing"))?
            .join(name);
        fs::create_dir(&path)
            .map_err(|error| TestError::infra(format!("create S13 {name}: {error}")))?;
        context.resources.register(
            "s13",
            format!("S13 case cgroup {name}"),
            Resource::Cgroup {
                path: path.clone(),
                inode: inode(&path).map_err(TestError::infra)?,
            },
        );
        self.cgroups.push(path.clone());
        Ok(path)
    }

    fn prepare_record_dir(&mut self) -> Result<(), TestError> {
        let parent = Path::new("/run/soglia");
        if !parent.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(parent).map_err(|error| {
                TestError::infra(format!("create /run/soglia trust anchor: {error}"))
            })?;
            self.created_trust_anchor = true;
        }
        let metadata = fs::symlink_metadata(parent)
            .map_err(|error| TestError::infra(format!("inspect /run/soglia: {error}")))?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S13 /run/soglia trust anchor is not root:root mode 0700 real directory",
            ));
        }
        fs::create_dir(&self.record_dir)
            .map_err(|error| TestError::infra(format!("create S13 record directory: {error}")))?;
        fs::set_permissions(&self.record_dir, fs::Permissions::from_mode(0o700))
            .map_err(|error| TestError::infra(format!("chmod S13 record directory: {error}")))
    }

    fn atomic_record(&self, record: &StateRecord) -> Result<(), TestError> {
        let temporary = self.record_dir.join(".state.json.tmp");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| TestError::infra(format!("create S13 record temp: {error}")))?;
        serde_json::to_writer(&mut file, record)
            .map_err(|error| TestError::infra(format!("serialize S13 record: {error}")))?;
        file.write_all(b"\n")
            .map_err(|error| TestError::infra(format!("write S13 record: {error}")))?;
        file.sync_all()
            .map_err(|error| TestError::infra(format!("sync S13 record: {error}")))?;
        fs::rename(&temporary, &self.record_path)
            .map_err(|error| TestError::infra(format!("publish S13 record: {error}")))?;
        File::open(&self.record_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| TestError::infra(format!("sync S13 record directory: {error}")))
    }

    fn read_record(&self) -> Result<StateRecord, ManagerFailure> {
        let metadata = fs::symlink_metadata(&self.record_path).map_err(|error| ManagerFailure {
            classification: Classification::Unknown,
            detail: format!("trusted record unavailable: {error}"),
        })?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(ManagerFailure {
                classification: Classification::Unknown,
                detail: "trusted record ownership/mode/type invalid".to_owned(),
            });
        }
        serde_json::from_slice(
            &fs::read(&self.record_path).map_err(|error| ManagerFailure {
                classification: Classification::Unknown,
                detail: error.to_string(),
            })?,
        )
        .map_err(|error| ManagerFailure {
            classification: Classification::Incompatible,
            detail: format!("record schema invalid: {error}"),
        })
    }

    fn validate_header(
        &self,
        record: &StateRecord,
        object_hash: &str,
    ) -> Result<(), ManagerFailure> {
        if record.magic != MAGIC
            || record.schema_version != SCHEMA
            || record.abi_version != ABI
            || record.object_sha256 != object_hash
            || record.state_id.len() != 32
            || record.generation == 0
            || !matches!(record.phase.as_str(), "INTENT" | "READY")
        {
            return Err(ManagerFailure {
                classification: Classification::Incompatible,
                detail: "trusted record header/schema/ABI/build is incompatible".to_owned(),
            });
        }
        if record.pin_root != self.pin_root.to_string_lossy() {
            return Err(ManagerFailure {
                classification: Classification::Unknown,
                detail: "trusted record names a different pin root".to_owned(),
            });
        }
        Ok(())
    }

    fn start(
        &self,
        context: &mut TestContext,
        cgroup: &Path,
        fault: Option<&str>,
    ) -> Result<StartOutcome, ManagerFailure> {
        let object_hash = self.object_hash(context).map_err(infra_manager)?;
        let mut ordering = Vec::new();
        let (classification, old_generation, swept) = if self.record_path.exists() {
            let old = self.read_record()?;
            self.validate_header(&old, &object_hash)?;
            if self.pin_root.exists() {
                self.validate_owned(context, &old)?;
                self.sweep(context, &old)?;
                ordering.push("validated compatible owned residue".to_owned());
                ordering.push("swept exact recorded objects and verified absence".to_owned());
            }
            (
                Classification::KnownCompatible,
                Some(old.generation),
                self.pin_root.exists() == false,
            )
        } else if self.pin_root.exists() {
            return Err(ManagerFailure {
                classification: Classification::Unknown,
                detail: "pin root exists without trusted ownership record".to_owned(),
            });
        } else {
            (Classification::Fresh, None, false)
        };
        let generation = old_generation.map_or(1, |value| value + 1);
        let state_id = new_state_id().map_err(infra_manager)?;
        let mut record = StateRecord {
            magic: MAGIC.to_owned(),
            schema_version: SCHEMA,
            abi_version: ABI,
            state_id,
            generation,
            phase: "INTENT".to_owned(),
            pin_root: self.pin_root.to_string_lossy().into_owned(),
            object_sha256: object_hash,
            cgroup_path: cgroup.to_string_lossy().into_owned(),
            cgroup_inode: inode(cgroup).map_err(|error| infra_manager(TestError::infra(error)))?,
            map_ids: serde_json::json!({}),
            programs: serde_json::json!([]),
            links: serde_json::json!([]),
        };
        self.atomic_record(&record).map_err(infra_manager)?;
        ordering.push("published durable INTENT".to_owned());
        if fault == Some("intent") {
            return Ok(StartOutcome {
                classification,
                old_generation,
                swept,
                record,
                ready_published: false,
                ordering,
            });
        }
        let internal_ready = self.record_dir.join("loader.ready");
        remove_file(&internal_ready).map_err(infra_manager)?;
        let loader = self
            .commands(context)
            .spawn(
                &CommandSpec::new(context.artifact("bin/s7-loader"))
                    .args([
                        self.object(context).into_os_string(),
                        cgroup.as_os_str().to_owned(),
                        self.pin_root.join("maps").into_os_string(),
                        self.pin_root.join("links").into_os_string(),
                        internal_ready.as_os_str().to_owned(),
                    ])
                    .timeout(Duration::from_secs(60)),
            )
            .map_err(|error| infra_manager(TestError::infra(error)))?;
        wait_for_path(&internal_ready, Duration::from_secs(10))
            .map_err(|error| infra_manager(TestError::infra(error)))?;
        ordering.push("created expected pinned maps/programs/links".to_owned());
        if fault == Some("pins") {
            stop_loader(loader).map_err(infra_manager)?;
            remove_file(&internal_ready).map_err(infra_manager)?;
            return Ok(StartOutcome {
                classification,
                old_generation,
                swept,
                record,
                ready_published: false,
                ordering,
            });
        }
        self.write_meta(context, &record).map_err(infra_manager)?;
        self.validate_kernel_contract(context, cgroup)
            .map_err(|detail| ManagerFailure {
                classification: Classification::Incompatible,
                detail,
            })?;
        ordering.push("bound soglia_meta and validated kernel object contracts".to_owned());
        if fault == Some("validated") {
            stop_loader(loader).map_err(infra_manager)?;
            remove_file(&internal_ready).map_err(infra_manager)?;
            return Ok(StartOutcome {
                classification,
                old_generation,
                swept,
                record,
                ready_published: false,
                ordering,
            });
        }
        stop_loader(loader).map_err(infra_manager)?;
        remove_file(&internal_ready).map_err(infra_manager)?;
        let (map_ids, programs, links) = self.manifest(context, cgroup).map_err(infra_manager)?;
        record.phase = "READY".to_owned();
        record.map_ids = map_ids;
        record.programs = programs;
        record.links = links;
        self.atomic_record(&record).map_err(infra_manager)?;
        ordering.push("published durable READY record".to_owned());
        if fault == Some("ready_record") {
            return Ok(StartOutcome {
                classification,
                old_generation,
                swept,
                record,
                ready_published: false,
                ordering,
            });
        }
        fs::write(
            &self.ready,
            format!("state_id={} generation={}\n", record.state_id, generation),
        )
        .map_err(|error| infra_manager(TestError::infra(format!("publish S13 ready: {error}"))))?;
        ordering.push("published startup.ready last".to_owned());
        Ok(StartOutcome {
            classification,
            old_generation,
            swept,
            record,
            ready_published: true,
            ordering,
        })
    }

    fn validate_owned(
        &self,
        context: &TestContext,
        record: &StateRecord,
    ) -> Result<(), ManagerFailure> {
        self.validate_inventory(false)?;
        self.validate_maps(context)
            .map_err(|detail| ManagerFailure {
                classification: Classification::Incompatible,
                detail,
            })?;
        if self.pin_root.join("maps/soglia_meta").exists() {
            let observed = self.meta_bytes(context).map_err(infra_manager)?;
            let expected = meta_bytes(record).map_err(infra_manager)?;
            if observed != vec![0; 48] && observed != expected {
                return Err(ManagerFailure {
                    classification: Classification::Unknown,
                    detail: "bpffs metadata does not match trusted record".to_owned(),
                });
            }
        }
        if record.phase == "READY" {
            let cgroup = Path::new(&record.cgroup_path);
            if !cgroup.exists() || inode(cgroup).ok() != Some(record.cgroup_inode) {
                return Err(ManagerFailure {
                    classification: Classification::Unknown,
                    detail: "recorded cgroup identity no longer matches".to_owned(),
                });
            }
            let (maps, programs, links) = self.manifest(context, cgroup).map_err(infra_manager)?;
            if maps != record.map_ids || programs != record.programs || links != record.links {
                return Err(ManagerFailure {
                    classification: Classification::Unknown,
                    detail: "kernel identities differ from trusted READY manifest".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_inventory(&self, require_full: bool) -> Result<(), ManagerFailure> {
        let mut observed = Vec::new();
        for directory in ["maps", "links"] {
            let root = self.pin_root.join(directory);
            if root.exists() {
                for entry in fs::read_dir(&root).map_err(|error| ManagerFailure {
                    classification: Classification::Unknown,
                    detail: error.to_string(),
                })? {
                    let entry = entry.map_err(|error| ManagerFailure {
                        classification: Classification::Unknown,
                        detail: error.to_string(),
                    })?;
                    observed.push(format!(
                        "{directory}/{}",
                        entry.file_name().to_string_lossy()
                    ));
                }
            }
        }
        let expected = MAPS
            .iter()
            .map(|name| format!("maps/{name}"))
            .chain(LINKS.iter().map(|name| format!("links/{name}")))
            .collect::<Vec<_>>();
        if observed.iter().any(|path| !expected.contains(path)) {
            return Err(ManagerFailure {
                classification: Classification::Unknown,
                detail: "unexpected object under recorded pin root".to_owned(),
            });
        }
        if require_full
            && expected
                .iter()
                .any(|path| !self.pin_root.join(path).exists())
        {
            return Err(ManagerFailure {
                classification: Classification::Incompatible,
                detail: "expected pin inventory incomplete".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_maps(&self, context: &TestContext) -> Result<(), String> {
        for (name, kind, key, value, max, flags) in expected_maps() {
            let path = self.pin_root.join("maps").join(name);
            if !path.exists() {
                continue;
            }
            let info = pinned_info(&self.commands(context), "map", &path).map_err(|e| e.detail)?;
            let observed = (
                info.get("type").and_then(Value::as_str).unwrap_or(""),
                info.get("bytes_key")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX),
                info.get("bytes_value")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX),
                info.get("max_entries")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX),
                info.get("flags")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX),
            );
            if observed != (kind, key, value, max, flags) {
                return Err(format!("map contract mismatch for {name}: {observed:?}"));
            }
        }
        Ok(())
    }

    fn validate_kernel_contract(&self, context: &TestContext, cgroup: &Path) -> Result<(), String> {
        self.validate_inventory(true)
            .map_err(|error| error.detail)?;
        self.validate_maps(context)?;
        let direct = json_cgroup(&self.commands(context), cgroup, false).map_err(|e| e.detail)?;
        if direct.as_array().map_or(0, Vec::len) != 6 {
            return Err("direct program set does not contain six hooks".to_owned());
        }
        let links =
            json_command(&self.commands(context), ["-j", "link", "show"]).map_err(|e| e.detail)?;
        let cgid = inode(cgroup)?;
        if links.as_array().map_or(0, |items| {
            items
                .iter()
                .filter(|link| {
                    link.get("type").and_then(Value::as_str) == Some("cgroup")
                        && link.get("cgroup_id").and_then(Value::as_u64) == Some(cgid)
                })
                .count()
        }) != 6
        {
            return Err("kernel cgroup-link contract does not contain six links".to_owned());
        }
        Ok(())
    }

    fn manifest(
        &self,
        context: &TestContext,
        cgroup: &Path,
    ) -> Result<(Value, Value, Value), TestError> {
        let mut map_ids = serde_json::Map::new();
        for name in MAPS {
            let info = pinned_info(
                &self.commands(context),
                "map",
                &self.pin_root.join("maps").join(name),
            )?;
            map_ids.insert(
                name.to_owned(),
                info.get("id")
                    .cloned()
                    .ok_or_else(|| TestError::infra("map id missing"))?,
            );
        }
        let mut programs = json_cgroup(&self.commands(context), cgroup, false)?;
        sort_json_array(&mut programs, "name");
        let cgid = inode(cgroup).map_err(TestError::infra)?;
        let mut links = json_command(&self.commands(context), ["-j", "link", "show"])?;
        if let Value::Array(items) = &mut links {
            items.retain(|link| {
                link.get("type").and_then(Value::as_str) == Some("cgroup")
                    && link.get("cgroup_id").and_then(Value::as_u64) == Some(cgid)
            });
            items.sort_by_key(|value| value.get("attach_type").map(Value::to_string));
        }
        Ok((Value::Object(map_ids), programs, links))
    }

    fn write_meta(&self, context: &TestContext, record: &StateRecord) -> Result<(), TestError> {
        let bytes = meta_bytes(record)?;
        let mut args = vec![
            OsString::from("map"),
            OsString::from("update"),
            OsString::from("pinned"),
            self.pin_root.join("maps/soglia_meta").into_os_string(),
            OsString::from("key"),
            OsString::from("hex"),
            OsString::from("00"),
            OsString::from("00"),
            OsString::from("00"),
            OsString::from("00"),
            OsString::from("value"),
            OsString::from("hex"),
        ];
        args.extend(
            bytes
                .iter()
                .map(|byte| OsString::from(format!("{byte:02x}"))),
        );
        let output = self
            .commands(context)
            .run(&CommandSpec::new("bpftool").args(args))
            .map_err(TestError::infra)?;
        require_success(&output, "write S13 metadata")
    }

    fn meta_bytes(&self, context: &TestContext) -> Result<Vec<u8>, TestError> {
        let value = dump_pin(
            &self.commands(context),
            &self.pin_root.join("maps/soglia_meta"),
        )?;
        value
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|entry| entry.get("value"))
            .and_then(Value::as_array)
            .ok_or_else(|| TestError::infra("S13 meta bytes missing"))?
            .iter()
            .map(|byte| {
                byte.as_str()
                    .and_then(|value| value.strip_prefix("0x"))
                    .and_then(|value| u8::from_str_radix(value, 16).ok())
                    .ok_or_else(|| TestError::infra("S13 meta byte invalid"))
            })
            .collect()
    }

    fn sweep(&self, context: &TestContext, record: &StateRecord) -> Result<(), ManagerFailure> {
        let old_links = record.links.as_array().cloned().unwrap_or_default();
        let old_maps = record
            .map_ids
            .as_object()
            .map(|values| {
                values
                    .values()
                    .filter_map(Value::as_u64)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for name in LINKS {
            remove_file(&self.pin_root.join("links").join(name)).map_err(infra_manager)?;
        }
        for name in MAPS {
            remove_file(&self.pin_root.join("maps").join(name)).map_err(infra_manager)?;
        }
        remove_empty(&self.pin_root.join("links")).map_err(infra_manager)?;
        remove_empty(&self.pin_root.join("maps")).map_err(infra_manager)?;
        remove_empty(&self.pin_root).map_err(infra_manager)?;
        let links =
            json_command(&self.commands(context), ["-j", "link", "show"]).map_err(infra_manager)?;
        let maps =
            json_command(&self.commands(context), ["-j", "map", "show"]).map_err(infra_manager)?;
        if old_links
            .iter()
            .filter_map(|link| link.get("id").and_then(Value::as_u64))
            .any(|id| contains_id(&links, id))
            || old_maps.into_iter().any(|id| contains_id(&maps, id))
        {
            return Err(ManagerFailure {
                classification: Classification::Unknown,
                detail: "recorded kernel IDs survived exact sweep".to_owned(),
            });
        }
        Ok(())
    }

    fn cleanup_managed(&self, context: &TestContext) -> Result<(), TestError> {
        if self.record_path.exists() {
            let record = self.read_record().map_err(manager_test)?;
            self.validate_header(&record, &self.object_hash(context)?)
                .map_err(manager_test)?;
            if self.pin_root.exists() {
                self.validate_owned(context, &record)
                    .map_err(manager_test)?;
                self.sweep(context, &record).map_err(manager_test)?;
            }
            remove_file(&self.record_path)?;
        }
        remove_file(&self.ready)?;
        remove_file(&self.record_dir.join("loader.ready"))?;
        Ok(())
    }
}

impl SpikeTest for S13 {
    type Observation = S13Observation;

    fn id(&self) -> TestId {
        TestId::S13
    }

    fn invariant(&self) -> &'static str {
        "trusted external ownership plus kernel-observed compatibility sweeps known residue before readiness, while incompatible and unknown pinned state fail closed without pathname deletion"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        self.baseline = Some((
            json_command(&self.commands(context), ["-j", "prog", "show"])?,
            json_command(&self.commands(context), ["-j", "link", "show"])?,
            json_command(&self.commands(context), ["-j", "map", "show"])?,
        ));
        <S1 as SpikeTest>::prepare(&mut self.fixture, context)?;
        self.fixture.unload_bpf()?;
        self.prepare_record_dir()?;
        context.resources.register(
            "s13",
            "S13 trusted ownership directory",
            Resource::Directory {
                path: self.record_dir.clone(),
            },
        );
        Ok(())
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let old = self.create_case_cgroup(context, "s13-old")?;
        let new = self.create_case_cgroup(context, "s13-new")?;
        let incompatible_new = self.create_case_cgroup(context, "s13-incompatible-new")?;
        let unknown = self.create_case_cgroup(context, "s13-unknown")?;
        let old_start = self.start(context, &old, None).map_err(manager_test)?;
        populate_stale(&self.commands(context), &self.pin_root)?;
        let old_policy = dump_named(&self.commands(context), &self.pin_root, "soglia_policy")?;
        let old_cookie = dump_named(&self.commands(context), &self.pin_root, "soglia_cookie_a")?;
        let old_tuple = dump_named(&self.commands(context), &self.pin_root, "soglia_tuples")?;
        let old_map_ids = old_start.record.map_ids.clone();
        remove_file(&self.ready)?;
        let recovered = self.start(context, &new, None).map_err(manager_test)?;
        let new_policy = dump_named(&self.commands(context), &self.pin_root, "soglia_policy")?;
        let new_cookie = dump_named(&self.commands(context), &self.pin_root, "soglia_cookie_a")?;
        let new_tuple = dump_named(&self.commands(context), &self.pin_root, "soglia_tuples")?;
        let new_map_ids = recovered.record.map_ids.clone();
        let current_maps = json_command(&self.commands(context), ["-j", "map", "show"])?;
        let current_programs = json_command(&self.commands(context), ["-j", "prog", "show"])?;
        let current_links = json_command(&self.commands(context), ["-j", "link", "show"])?;
        let old_kernel_ids_absent = ids_from_object(&old_map_ids)
            .into_iter()
            .all(|id| !contains_id(&current_maps, id))
            && ids_from_array(&old_start.record.programs)
                .into_iter()
                .all(|id| !contains_id(&current_programs, id))
            && ids_from_array(&old_start.record.links)
                .into_iter()
                .all(|id| !contains_id(&current_links, id));
        let compatible = CompatibleCase {
            old_record: old_start.record.clone(),
            new_record: recovered.record.clone(),
            old_map_ids,
            new_map_ids,
            old_policy,
            old_cookie,
            old_tuple,
            new_policy,
            new_cookie,
            new_tuple: new_tuple.clone(),
            old_tuple_lookup_after_recovery: !new_tuple.as_array().is_some_and(Vec::is_empty),
            old_kernel_ids_absent,
            ready_after_recovery: self.ready.exists(),
            ordering: recovered.ordering.clone(),
        };

        let compatible_record = self.read_record().map_err(manager_test)?;
        populate_stale(&self.commands(context), &self.pin_root)?;
        let incompatible_content =
            dump_named(&self.commands(context), &self.pin_root, "soglia_tuples")?;
        let mut mutated = compatible_record.clone();
        mutated.abi_version = 2;
        self.atomic_record(&mutated)?;
        remove_file(&self.ready)?;
        let failure = self
            .start(context, &incompatible_new, None)
            .expect_err("incompatible S13 state must fail");
        let incompatible = RefusalCase {
            classification: failure.classification,
            detail: failure.detail,
            ready: self.ready.exists(),
            ids_before: compatible_record.map_ids.clone(),
            ids_after: self.manifest(context, &new)?.0,
            content_before: incompatible_content.clone(),
            content_after: dump_named(&self.commands(context), &self.pin_root, "soglia_tuples")?,
        };
        self.atomic_record(&compatible_record)?;
        self.cleanup_managed(context)?;

        fs::create_dir_all(self.pin_root.join("maps"))
            .map_err(|error| TestError::infra(format!("create S13 unknown root: {error}")))?;
        let foreign_pin = self.pin_root.join("maps/soglia_policy");
        create_foreign_map(&self.commands(context), &foreign_pin)?;
        let foreign_before = pinned_info(&self.commands(context), "map", &foreign_pin)?;
        let foreign_content_before = dump_pin(&self.commands(context), &foreign_pin)?;
        let unknown_failure = self
            .start(context, &unknown, None)
            .expect_err("unknown S13 state must fail");
        let foreign_after = pinned_info(&self.commands(context), "map", &foreign_pin)?;
        let foreign_content_after = dump_pin(&self.commands(context), &foreign_pin)?;
        let unknown = RefusalCase {
            classification: unknown_failure.classification,
            detail: unknown_failure.detail,
            ready: self.ready.exists(),
            ids_before: foreign_before,
            ids_after: foreign_after,
            content_before: foreign_content_before,
            content_after: foreign_content_after,
        };
        remove_file(&foreign_pin)?;
        remove_empty(&self.pin_root.join("maps"))?;
        remove_empty(&self.pin_root)?;

        let mut crash_cases = Vec::new();
        for fault in ["intent", "pins", "validated", "ready_record"] {
            let crash_old = self.create_case_cgroup(context, &format!("s13-crash-{fault}-old"))?;
            let crash_new = self.create_case_cgroup(context, &format!("s13-crash-{fault}-new"))?;
            let faulted = self
                .start(context, &crash_old, Some(fault))
                .map_err(manager_test)?;
            let ready_at_fault = self.ready.exists();
            let record_at_fault = self.read_record().map_err(manager_test)?;
            let recovery = self
                .start(context, &crash_new, None)
                .map_err(manager_test)?;
            crash_cases.push(CrashCase {
                fault: fault.to_owned(),
                ready_at_fault,
                record_at_fault,
                recovery,
            });
            self.cleanup_managed(context)?;
            let _ = faulted;
        }
        Ok(S13Observation {
            contract: serde_json::json!({
                "trust_anchor": self.record_path,
                "record_mode": "root:root 0600 inside root:root 0700 real directories",
                "fields": ["magic","schema_version","abi_version","state_id","generation","phase","pin_root","object_sha256","cgroup_path","cgroup_inode","kernel_object_ids"],
                "meta_role": "corroborating binding only; never an authorization input or sole ownership proof",
                "write_ahead_order": ["classify","exact sweep","INTENT","pins","meta","kernel validation","READY record","startup.ready"],
                "unknown_rule": "fail closed and leave untouched",
            }),
            original_historical_failure_preserved: true,
            baseline_programs: self
                .baseline
                .as_ref()
                .map(|v| v.0.clone())
                .unwrap_or_default(),
            baseline_links: self
                .baseline
                .as_ref()
                .map(|v| v.1.clone())
                .unwrap_or_default(),
            baseline_maps: self
                .baseline
                .as_ref()
                .map(|v| v.2.clone())
                .unwrap_or_default(),
            compatible,
            incompatible,
            unknown,
            stale_generation_authorized_new: false,
            crash_cases,
            broad_name_cleanup_used: false,
            production_backend_implemented: false,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        let compatible = &observation.compatible;
        if compatible.old_record.generation + 1 != compatible.new_record.generation
            || compatible.old_record.state_id == compatible.new_record.state_id
            || compatible.old_map_ids == compatible.new_map_ids
            || !compatible.old_kernel_ids_absent
            || !compatible.ready_after_recovery
            || compatible.old_tuple_lookup_after_recovery
            || !compatible.new_policy.as_array().is_some_and(Vec::is_empty)
            || !compatible.new_cookie.as_array().is_some_and(Vec::is_empty)
            || !compatible.new_tuple.as_array().is_some_and(Vec::is_empty)
            || compatible.ordering.last().map(String::as_str)
                != Some("published startup.ready last")
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S13 compatible state was not safely swept/recreated before readiness",
            ));
        }
        if observation.incompatible.classification != Classification::Incompatible
            || observation.incompatible.ready
            || observation.incompatible.ids_before != observation.incompatible.ids_after
            || observation.incompatible.content_before != observation.incompatible.content_after
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S13 incompatible owned state did not fail closed unchanged",
            ));
        }
        if observation.unknown.classification != Classification::Unknown
            || observation.unknown.ready
            || observation.unknown.ids_before != observation.unknown.ids_after
            || observation.unknown.content_before != observation.unknown.content_after
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S13 unknown foreign pin was trusted, changed, or deleted by pathname",
            ));
        }
        if observation.stale_generation_authorized_new
            || observation.broad_name_cleanup_used
            || observation.production_backend_implemented
            || observation.crash_cases.len() != 4
            || observation.crash_cases.iter().any(|case| {
                case.ready_at_fault
                    || !case.recovery.ready_published
                    || case.recovery.classification != Classification::KnownCompatible
                    || case.recovery.record.generation != case.record_at_fault.generation + 1
            })
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S13 generation, write-ahead crash recovery, or scope invariant was not proven",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if self.record_path.exists() {
            self.cleanup_managed(context)?;
        }
        if self.pin_root.exists() {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S13 refuses unowned residual pin root during cleanup",
            ));
        }
        for cgroup in self.cgroups.iter().rev() {
            remove_empty(cgroup)?;
        }
        self.cgroups.clear();
        remove_file(&self.ready)?;
        if self.record_dir.exists() {
            remove_empty(&self.record_dir)?;
        }
        let fixture_result = <S1 as SpikeTest>::cleanup(&mut self.fixture, context);
        if self.created_trust_anchor && Path::new("/run/soglia").exists() {
            remove_empty(Path::new("/run/soglia"))?;
            self.created_trust_anchor = false;
        }
        fixture_result
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::verify_cleanup(&self.fixture, context)?;
        let (programs, links, maps) = self
            .baseline
            .as_ref()
            .ok_or_else(|| TestError::infra("S13 baseline missing"))?;
        let clean = stable_bpf(programs)
            == stable_bpf(&json_command(
                &self.commands(context),
                ["-j", "prog", "show"],
            )?)
            && stable_bpf(links)
                == stable_bpf(&json_command(
                    &self.commands(context),
                    ["-j", "link", "show"],
                )?)
            && stable_bpf(maps)
                == stable_bpf(&json_command(
                    &self.commands(context),
                    ["-j", "map", "show"],
                )?)
            && !self.pin_root.exists()
            && !self.record_dir.exists()
            && !self.ready.exists();
        context.evidence.write_json("s13/independent-cleanup.json", &serde_json::json!({"clean":clean,"pin_root_absent":!self.pin_root.exists(),"record_absent":!self.record_dir.exists(),"ready_absent":!self.ready.exists()}))
            .map_err(|error| TestError::infra(format!("write S13 cleanup: {error}")))?;
        if !clean {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S13 independent BPF/ownership baseline was not restored",
            ));
        }
        Ok(())
    }
}

fn expected_maps() -> Vec<(&'static str, &'static str, u64, u64, u64, u64)> {
    vec![
        ("soglia_policy", "hash", 8, 16, 1024, 0),
        ("soglia_tuples", "hash", 16, 64, 4096, 0),
        ("soglia_cookie_a", "hash", 8, 8, 4096, 0),
        ("soglia_sk_b", "sk_storage", 4, 8, 0, 1),
        ("soglia_events", "ringbuf", 0, 0, 65536, 0),
        ("soglia_counters", "array", 4, 8, 9, 0),
        ("soglia_denies", "hash", 8, 8, 1024, 0),
        ("soglia_meta", "array", 4, 48, 1, 0),
        ("soglia_diag_entries", "array", 4, 8, 7, 0),
        ("soglia_port_diag", "array", 4, 4, 12, 0),
    ]
}

fn new_state_id() -> Result<String, TestError> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| TestError::infra(format!("generate S13 state id: {error}")))?;
    Ok(hex(&bytes))
}

fn meta_bytes(record: &StateRecord) -> Result<Vec<u8>, TestError> {
    let state = (0..record.state_id.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&record.state_id[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TestError::infra(format!("decode S13 state id: {error}")))?;
    let mut bytes = b"SOGLIABP".to_vec();
    bytes.extend_from_slice(&SCHEMA.to_ne_bytes());
    bytes.extend_from_slice(&ABI.to_ne_bytes());
    bytes.extend_from_slice(&state);
    bytes.extend_from_slice(&record.generation.to_ne_bytes());
    Ok(bytes)
}

fn populate_stale(commands: &CommandExecutor, root: &Path) -> Result<(), TestError> {
    update_map(
        commands,
        &root.join("maps/soglia_policy"),
        &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        &[
            1, 0, 0, 0, 0, 0, 0, 0, 0x55, 0x44, 0x33, 0x22, 0x11, 0, 0, 0,
        ],
    )?;
    update_map(
        commands,
        &root.join("maps/soglia_cookie_a"),
        &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        &[1, 0x70, 0, 0, 0, 0, 0, 0],
    )?;
    let mut value = vec![0_u8; 64];
    value[0..8].copy_from_slice(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    value[8..16].copy_from_slice(&[1, 0x70, 0, 0, 0, 0, 0, 0]);
    update_map(
        commands,
        &root.join("maps/soglia_tuples"),
        &[
            0x0a, 0xc9, 0, 1, 0x0a, 0xc8, 0xff, 1, 0x28, 0xa0, 0, 0, 0x99, 0x3a, 0, 0,
        ],
        &value,
    )
}

fn create_foreign_map(commands: &CommandExecutor, pin: &Path) -> Result<(), TestError> {
    let output = commands
        .run(&CommandSpec::new("bpftool").args([
            OsString::from("map"),
            OsString::from("create"),
            pin.as_os_str().to_owned(),
            OsString::from("type"),
            OsString::from("array"),
            OsString::from("key"),
            OsString::from("4"),
            OsString::from("value"),
            OsString::from("8"),
            OsString::from("entries"),
            OsString::from("1"),
            OsString::from("name"),
            OsString::from("s13_foreign"),
        ]))
        .map_err(TestError::infra)?;
    require_success(&output, "create S13 foreign map")?;
    update_map(commands, pin, &[0, 0, 0, 0], &[0x13, 0, 0, 0, 0, 0, 0, 0])
}

fn update_map(
    commands: &CommandExecutor,
    pin: &Path,
    key: &[u8],
    value: &[u8],
) -> Result<(), TestError> {
    let mut args = vec![
        OsString::from("map"),
        OsString::from("update"),
        OsString::from("pinned"),
        pin.as_os_str().to_owned(),
        OsString::from("key"),
        OsString::from("hex"),
    ];
    args.extend(key.iter().map(|b| OsString::from(format!("{b:02x}"))));
    args.extend([OsString::from("value"), OsString::from("hex")]);
    args.extend(value.iter().map(|b| OsString::from(format!("{b:02x}"))));
    let output = commands
        .run(&CommandSpec::new("bpftool").args(args))
        .map_err(TestError::infra)?;
    require_success(&output, "update S13 pinned map")
}

fn pinned_info(commands: &CommandExecutor, kind: &str, path: &Path) -> Result<Value, TestError> {
    let output = commands
        .run(&CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from(kind),
            OsString::from("show"),
            OsString::from("pinned"),
            path.as_os_str().to_owned(),
        ]))
        .map_err(TestError::infra)?;
    require_success(&output, "inspect S13 pin")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|e| TestError::infra(format!("parse S13 pin: {e}")))
}
fn dump_pin(commands: &CommandExecutor, path: &Path) -> Result<Value, TestError> {
    let output = commands
        .run(&CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from("map"),
            OsString::from("dump"),
            OsString::from("pinned"),
            path.as_os_str().to_owned(),
        ]))
        .map_err(TestError::infra)?;
    require_success(&output, "dump S13 pin")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|e| TestError::infra(format!("parse S13 dump: {e}")))
}
fn dump_named(commands: &CommandExecutor, root: &Path, name: &str) -> Result<Value, TestError> {
    dump_pin(commands, &root.join("maps").join(name))
}
fn stop_loader(loader: RunningCommand) -> Result<(), TestError> {
    let pid = loader.id();
    kill(
        Pid::from_raw(i32::try_from(pid).map_err(|e| TestError::infra(e.to_string()))?),
        Signal::SIGKILL,
    )
    .map_err(|e| TestError::infra(e.to_string()))?;
    let _ = loader
        .wait(Duration::from_secs(5))
        .map_err(TestError::infra)?;
    Ok(())
}
fn sort_json_array(value: &mut Value, key: &str) {
    if let Value::Array(items) = value {
        items.sort_by_key(|item| item.get(key).map(Value::to_string));
    }
}
fn contains_id(value: &Value, id: u64) -> bool {
    value.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("id").and_then(Value::as_u64) == Some(id))
    })
}
fn ids_from_object(value: &Value) -> Vec<u64> {
    value
        .as_object()
        .into_iter()
        .flat_map(|o| o.values())
        .filter_map(Value::as_u64)
        .collect()
}
fn ids_from_array(value: &Value) -> Vec<u64> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.get("id").and_then(Value::as_u64))
        .collect()
}
fn infra_manager(error: TestError) -> ManagerFailure {
    ManagerFailure {
        classification: Classification::Unknown,
        detail: error.detail,
    }
}
fn manager_test(error: ManagerFailure) -> TestError {
    TestError::new(
        match error.classification {
            Classification::Incompatible => Verdict::Unproven,
            _ => Verdict::Unproven,
        },
        error.detail,
    )
}
fn require_success(output: &CommandOutput, context: &str) -> Result<(), TestError> {
    output.require_success(context).map_err(TestError::infra)
}
fn remove_file(path: &Path) -> Result<(), TestError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(TestError::infra(format!("remove {}: {e}", path.display()))),
    }
}
fn remove_empty(path: &Path) -> Result<(), TestError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(TestError::infra(format!(
            "remove directory {}: {e}",
            path.display()
        ))),
    }
}
fn stable_bpf(value: &Value) -> Value {
    let mut v = value.clone();
    strip(&mut v);
    v
}
fn strip(value: &mut Value) {
    match value {
        Value::Array(v) => v.iter_mut().for_each(strip),
        Value::Object(o) => {
            for k in [
                "id",
                "loaded_at",
                "run_time_ns",
                "run_cnt",
                "recursion_misses",
            ] {
                o.remove(k);
            }
            o.values_mut().for_each(strip)
        }
        _ => {}
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
