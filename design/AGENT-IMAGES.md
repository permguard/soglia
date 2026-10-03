<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Agent images

## Status and scope

Status: `APPROVED`.

This document defines how Soglia identifies, verifies, stores and prepares an agent supplied as an OCI image.
It applies to every sandbox profile: `runc`, `gvisor` and `firecracker`.
It closes the image and immutable-template part of I8 and supplies the bounded artifact-store behavior required by R3 through R5.
It does not change the currently qualified rootfs-path configuration; implementation follows in Phase 3.

The image pipeline runs before call admission.
No registry access, signature verification, layer download, unpack or disk conversion may occur in the path of an admitted call.

## Security properties

An admitted agent image has all of these properties:

1. Its reference names one immutable OCI manifest by digest.
2. Every manifest, configuration object and layer is verified against the digest named by its parent object.
3. The manifest satisfies the configured signer and provenance policy.
4. Its selected platform and entry point are explicit and compatible with the selected sandbox profile.
5. Its unpacked or converted artifact is content-addressed, immutable and read-only.
6. Preparation never materializes an archive entry outside its private staging directory or preserves executable privilege metadata.
7. Store occupancy and all live references are bounded and observable.
8. Garbage collection never removes an artifact referenced by an active Execution or prepared template.
9. Failure is typed and leaves the previous trusted artifact and active Executions unchanged.

## Image reference

The production configuration accepts only the canonical form:

```text
registry.example/repository/name@sha256:<64 lowercase hexadecimal characters>
```

Tags, implicit tags, local names without a registry and digest algorithms other than an explicitly supported algorithm are rejected before network access.
The manifest digest is the stable image identity recorded in configuration resolution, durable template state, events and qualification evidence.
Logs may contain the registry host, repository and abbreviated digest, but never registry credentials or bearer tokens.

An OCI index is allowed only when the selected child manifest is deterministic from the configured platform tuple.
The resolved child-manifest digest is recorded alongside the index digest.
An index that has zero or multiple compatible children is rejected.

## Migration from rootfs paths

The current `agents.<name>.rootfs` setting points directly at a host directory and remains the qualified compatibility mode.
The new configuration uses an `image` object and cannot be combined with `rootfs` for the same agent.

```yaml
agents:
  echo:
    image:
      reference: registry.example/agents/echo@sha256:0123...cdef
      trust_policy: production-agents
      provenance_policy: nitro-release
    command: ["/agent", "--serve"]
```

The parser rejects both fields present and both fields absent.
Rootfs-path mode keeps its current behavior and evidence label, but never claims the OCI trust or immutable-store properties in this document and never satisfies I8.
Every startup that admits a rootfs-path agent emits a structured deprecation event.
Rootfs-path mode remains supported for two releases after OCI images are declared stable, and is removed in the following release.
Migration is explicit: an operator imports and verifies the digest, changes the configuration, runs a dry validation, and then restarts Soglia.
There is no automatic conversion of an arbitrary host directory into a trusted image.

## Trust policy

### Signature verification

Every imported manifest is verified with Sigstore-compatible verification.
There is no implicit default policy: every image-backed agent names a trust policy, and an agent without one is rejected.
A named trust policy declares one or more allowed signer identities and one verification mode:

- key verification against pinned public keys or certificates, for air-gapped deployments;
- keyless verification against pinned OIDC issuer and subject identities, for public CI;
- a conjunction of key and keyless requirements when a deployment requires independent signers.

The policy itself is trusted configuration and is fingerprinted in durable evidence.
Verification is fail-closed when no configured identity matches.
A valid signature by an unlisted identity is not sufficient.

The stored verification record contains the image digest, policy digest, signer identity, certificate chain or key identifier, transparency-log bundle when applicable, verification time and verifier version.
Raw credentials and registry bearer tokens are never stored in that record.

### Offline verification and time

An online import stores the complete verification bundle needed for later offline verification: signature, certificate chain, trusted root identity, transparency-log inclusion proof and signed checkpoint or equivalent bundle material.
Offline startup re-verifies the bundle and the local content digests without contacting the registry or transparency service.
An incomplete bundle cannot be treated as previously verified.

A signing certificate is evaluated at signing time, as proven by the transparency-log integrated time, following the Sigstore model.
Certificate expiry after a valid signing time does not invalidate the artifact.
Revocation is expressed by a trusted deny-list of image digests and signer identities, or by trust-root rotation.
A deny-list or trust-root change invalidates the cached verification decision for new admissions.
It does not mutate an artifact used by an already active Execution.

### Provenance

A provenance policy may require an in-toto attestation whose predicate is compatible with the configured SLSA level.
The attestation subject must equal the admitted manifest digest.
Policy can constrain builder identity, source repository, source revision, build type and whether the build was hermetic.

Provenance is optional as a mechanism.
The reference production policy shipped with Soglia requires it.
Absence of an attestation under a policy that requires it is a typed trust refusal, not a registry or parsing error.

### Future Permguard decision

The trust-policy result is a stable input to a future Permguard authorization decision.
That decision can bind tenant, agent name, image digest, signer identity, provenance builder and sandbox profile.
The image pipeline exposes these values without making the artifact store depend on a specific policy engine implementation.

## Registry and download contract

Downloads happen through an explicit prepare operation or bounded startup prefetch, never while serving a call.
The prepare operation is idempotent by manifest digest.

Registry access requires:

- TLS with certificate and hostname verification;
- credentials supplied by a bounded credential provider or standard read-only credential file;
- no credentials in arguments, logs, events, durable image metadata or evidence;
- separate connect, response-header, body-idle and total-operation deadlines;
- a maximum compressed size for each blob;
- a maximum compressed size for the complete image;
- a maximum uncompressed size, file count and path length before extraction begins;
- bounded redirects restricted to an approved scheme and registry policy;
- bounded retries with jitter outside the call path.

The registry client streams every object into a private temporary file while hashing it.
The object becomes visible in the content-addressed store only after its digest and declared size match, the file is flushed, and an atomic rename succeeds.
A partial or oversized object is deleted by exact staging path and never enters the trusted store.

Authentication failure, TLS failure, timeout, digest mismatch and registry absence remain distinct diagnostic reasons even when several map to the same process-level refusal class.

## Content-addressed store

The store has separate namespaces for immutable source objects, verification records, quarantined objects and derived profile artifacts:

```text
<state>/images/
  blobs/sha256/<digest>
  manifests/sha256/<digest>.json
  verification/<policy-digest>/<manifest-digest>.json
  quarantine/sha256/<digest>
  rootfs/<manifest-digest>/<unpacker-version>/
  disks/<manifest-digest>/<converter-version>/<guest-abi>/disk.erofs
  leases/<execution-or-template-id>.json
  staging/<random-owned-id>/
```

Every persistent path is derived from a validated lowercase digest or a Soglia-generated identifier.
No registry-provided path component is used directly in a host path.
Store directories have a trusted owner, fixed permissions and no symlink ancestors.

Preparation uses a private staging directory on the same filesystem as the final artifact.
The completed artifact receives a manifest containing every input digest, tool version, normalized metadata policy and resulting artifact digest.
Publication is an atomic rename followed by verification through the final path.
An existing artifact is reused only when its complete manifest and filesystem identity match.

Objects downloaded for an image that then fails signature or provenance verification move to `quarantine/`.
Quarantine has its own byte and object bound, is never used to admit an image, and is emptied by store garbage collection.

## Safe unpacking

Each layer digest is checked before its tar stream is interpreted.
Extraction uses descriptor-relative operations beneath a trusted staging-directory file descriptor.
It never joins an archive string to an ambient host path and never follows a symlink while creating a later entry.

The following rules are normative:

- absolute paths, empty paths, `..` components, NUL bytes and paths exceeding the configured limit are rejected;
- device nodes, sockets and FIFOs are rejected;
- setuid and setgid bits are rejected rather than preserved;
- file capabilities and every xattr are rejected; an allow-list requires a later approved design;
- a symlink is accepted only when its lexical target remains within the image root from the symlink's parent;
- a hardlink is accepted only to a previously materialized regular file in the same staged root;
- ownership is numeric, bounded and validated for the user-namespace mapping;
- timestamps and mode bits are normalized according to a versioned unpack policy;
- OCI whiteouts are interpreted as layer operations and are never materialized as device nodes;
- malformed whiteouts, whiteouts outside the staged root and opaque-directory markers in an invalid position are rejected;
- duplicate entries whose meaning depends on extractor behavior are rejected unless the versioned OCI layer rule defines an unambiguous replacement.

Layer application happens in order in one private staging tree.
Failure removes only the exact staging tree owned by the operation.
No partially unpacked rootfs is published.

After validation, the rootfs is made immutable to the runtime.
The `runc` implementation uses an exact read-only bind mount whose source lives in the protected store.
EROFS for `runc` is not part of the initial implementation, because it would add loop devices and their churn to the privileged path.
The runtime verifies read-only mount flags and artifact identity before creating an Execution.

## Budgets and admission

The image store has explicit independent limits.
The initial values below are qualification targets for the supported deployment envelope:

| Limit                                       | Initial value      |
| ------------------------------------------- | ------------------ |
| Compressed bytes per layer                  | 1 GiB              |
| Compressed bytes per image                  | 2 GiB              |
| Uncompressed bytes per image                | 8 GiB              |
| Files and directories per image             | 200,000            |
| Total store bytes                           | 20 GiB, configured |
| Concurrent prepare operations               | 2                  |

The store also bounds total unpacked-rootfs inodes, total converted-disk bytes, retained unreferenced digests, quarantine bytes and the time spent downloading, verifying, unpacking and converting.

Space for the complete operation is reserved before download or conversion begins.
Reservation includes worst-case uncompressed output and temporary staging overhead.
The operation is refused before consuming registry bandwidth when a safe reservation cannot be made.

Every active Execution, prepared template and in-progress preparation owns a durable lease on the manifest digest and the exact derived artifact.
Reference counts are reconstructed from those trusted leases rather than trusted as a standalone mutable counter.
Garbage collection takes a store-wide generation lock, snapshots trusted leases, marks eligible unreferenced artifacts and revalidates the mark immediately before each exact removal.
An artifact that gains a reference is not removed.
Active and prepared artifacts are never eviction candidates.

Removal proceeds from derived artifacts to verification records, then quarantine, then unreferenced blobs.
Every unlink is exact and verified.
Unknown files, mismatched identities or untrusted store metadata stop garbage collection and preserve the state for inspection.

Garbage collection runs on an explicit operator command and automatically when store occupancy crosses a configured high-water mark.
Neither trigger runs in a call path, and both are bounded in duration and work per pass.
Capacity saturation is a typed refusal and never triggers opportunistic deletion in a call path.

Metrics expose capacity, reserved bytes, used bytes, object counts, active leases, preparation queue occupancy, high-water marks, rejected reservations and garbage-collection results without using tenant or digest as unbounded metric labels.

## Profile-specific artifacts

### runc

`runc` receives the verified unpacked rootfs through a read-only bind mount.
The OCI bundle records the immutable artifact identity in its durable ownership state.
Writable state is limited to separately declared bounded tmpfs mounts and the private Execution volume.

### gVisor

`gvisor` consumes the same verified rootfs and read-only mount contract.
Its capability probe and qualification independently prove that the runtime cannot remount or mutate the store artifact.

### Firecracker

Firecracker never boots directly from an unpacked host directory.
The verified rootfs is converted once per tuple of manifest digest, converter version and guest ABI into a content-addressed read-only EROFS disk.
The disk image is verified after conversion and never modified in place.
Each microVM receives separate writable ephemeral storage, and a snapshot or template refers to the immutable base-disk identity.

The EROFS format, the converter and the guest ABI are part of the profile's trust and qualification boundary.
Changing any one produces a different artifact key and requires conversion again.

## User-namespace interaction

SOG-3.02 defines the final UID/GID map.
This design preserves bounded numeric ownership from the image but never chowns the shared immutable rootfs for one Execution.
Ownership is translated with idmapped mounts.
A kernel or filesystem without idmapped-mount support refuses image-backed agents with a typed `Unsupported` refusal; there is no fallback.
Every mapped image ID must fit entirely within the configured subordinate-ID range.

An image containing an unmappable owner is refused during preparation.
No fallback to host-root ownership, recursive per-call chown or a wider user-namespace map is allowed.
Read-only image data stays shared between Executions without sharing writable state.

## Failure semantics

Image failures carry a stable image-specific reason and a process-level refusal class.
This design adds two stable process-level classes to the existing table:

| Exit status | Class       | Meaning                                                              |
| ----------- | ----------- | -------------------------------------------------------------------- |
| `25`        | `Untrusted` | The artifact failed the configured signature or provenance policy    |
| `26`        | `Capacity`  | A declared artifact budget cannot be reserved                        |

`Unknown` keeps its existing meaning: trusted state whose ownership or identity cannot be proved, preserved for operator inspection.

| Condition                              | Image reason           | Refusal class    | Host mutation                         |
| -------------------------------------- | ---------------------- | ---------------- | ------------------------------------- |
| Non-digest or malformed reference      | `INVALID_REFERENCE`    | `Incompatible`   | None                                  |
| Manifest or layer digest mismatch      | `DIGEST_MISMATCH`      | `Incompatible`   | Exact staging object removed          |
| Unsupported media type or platform     | `UNSUPPORTED_FORMAT`   | `Unsupported`    | Exact staging object removed, if any  |
| Signature or signer-policy failure     | `UNTRUSTED_SIGNATURE`  | `Untrusted`      | Downloaded objects quarantined        |
| Required provenance absent or invalid  | `UNTRUSTED_PROVENANCE` | `Untrusted`      | Downloaded objects quarantined        |
| Forbidden or malformed archive entry   | `UNSAFE_LAYER_ENTRY`   | `Incompatible`   | Exact staging tree removed            |
| Registry object absent                 | `DIGEST_NOT_FOUND`     | `Infrastructure` | None                                  |
| Registry, TLS, auth or I/O unavailable | `REGISTRY_UNAVAILABLE` | `Infrastructure` | Partial staging removed               |
| Artifact budget cannot be reserved     | `ARTIFACT_CAPACITY`    | `Capacity`       | None                                  |
| Idmapped mounts unavailable            | `IDMAP_UNSUPPORTED`    | `Unsupported`    | None                                  |
| Trusted-store identity is inconsistent | `STORE_INTEGRITY`      | `Unknown`        | State preserved                       |

No failure mutates a previously published artifact.
Unknown trusted-store state is preserved, stops image admission and requires operator inspection.
A registry outage does not invalidate a complete locally stored artifact whose signature, provenance and content can be reverified offline.

## Recovery

At startup Soglia classifies every staging operation and published artifact before mutation.
A staging directory with a valid owned intent can be resumed or removed by exact paths according to its phase.
A complete artifact with missing or discordant publication metadata is `Unknown` and preserved.
A publication record whose artifact is absent is also `Unknown`.

Recovery never downloads implicitly while classifying local state.
Once classification succeeds, an operator-selected prepare operation may resume network work within the normal deadlines and budgets.
Active leases are rebuilt from durable Execution and template ownership records before garbage collection is enabled.

## Qualification plan

The image gate is added to `spike:qualify` and shares its production baseline and clean harness fingerprint.
Evidence is measured before harness teardown and includes source-object digests, policy digests, derived-artifact identity, store occupancy and cleanup.

### Positive cases

- signed single-manifest image by digest, prepared online and used by `runc`;
- the same digest prepared again without network access or unpacking;
- offline verification from a complete stored verification bundle;
- a signature whose certificate expired after the proven signing time;
- OCI index with one exact supported platform;
- two simultaneous prepare requests for one digest yielding one published artifact;
- active Executions sharing only immutable rootfs data through idmapped read-only mounts;
- garbage collection of an unused digest and of quarantine, followed by return to the store baseline;
- conversion of the same verified digest for Firecracker, when that profile exists, yielding one immutable EROFS disk per converter and guest-ABI tuple.

### Negative and adversarial cases

- mutable tag and digest-less reference;
- an agent without a named trust policy;
- manifest changed under the same requested identity;
- invalid, wrong-identity or untrusted signature, and a certificate invalid at signing time;
- a digest or signer identity on the deny-list;
- required provenance absent, wrong subject, wrong builder or wrong source revision;
- tampered layer, wrong layer size and truncated transfer;
- path traversal, absolute path, escaping symlink, escaping hardlink and duplicate-entry ambiguity;
- device node, setuid or setgid bit, file capability, any xattr and malformed whiteout;
- compressed, uncompressed, inode, file-count, quarantine and total-store budgets exhausted independently;
- registry timeout, TLS failure, authentication failure and object not found;
- crash after each durable boundary of download, verification, quarantine, unpack, conversion, publication, lease creation and garbage collection;
- an artifact in use while garbage collection runs;
- a digest becoming referenced between mark and exact removal;
- unknown file or identity mismatch in the trusted store;
- an owner outside the SOG-3.02 UID/GID map, and a host without idmapped-mount support;
- mutation attempts from `runc`, `gvisor` and Firecracker guest paths.

PASS requires typed outcomes, no use of an unverified artifact, no mutation of a published artifact, no removal of an in-use artifact, exact cleanup of owned staging state and return to the declared resource baseline.
The aggregate verifier checks these properties and rejects missing cases or a different image-policy digest.

## Observability

Structured bounded events report:

- prepare admitted, deduplicated, completed or refused;
- image reason and process-level refusal class;
- durations of registry access, verification, unpack and conversion;
- bytes reserved, downloaded, quarantined, unpacked, converted and reclaimed;
- store capacities, occupancy and high-water marks;
- active leases and unreferenced candidates;
- garbage-collection trigger, result and exact object counts;
- offline versus online verification and the verifier and policy versions;
- every admission of a deprecated rootfs-path agent.

Digests are permitted in trusted diagnostic evidence but not as unbounded production metric labels.
Registry credentials, signature private material and bearer tokens never enter logs or evidence.

## Alternatives rejected

### Pull on every call

Rejected because availability, latency, registry credentials and unbounded bytes would enter the call path.
It also makes one call's admission depend on mutable external state after policy evaluation.

### Mutable tags

Rejected because the same configuration could execute different code at different times and qualification evidence could not bind the executed artifact.

### Writable shared overlay

Rejected because one Execution could affect another and an image could accumulate state across calls.
Writable data belongs only to an Execution-specific bounded volume or tmpfs.

### Generic archive extraction

Rejected because common extractors differ on path traversal, hardlinks, whiteouts, devices and xattrs.
The qualified unpacker implements the narrow OCI rules above with descriptor-relative filesystem operations.

### Trusting registry TLS alone

Rejected because TLS authenticates transport and registry service, not the authorized publisher, provenance or reproducibility of the agent artifact.

### Per-Execution copy and chown of the rootfs

Rejected because it creates unbounded I/O and inode churn and prevents efficient sharing of immutable data.
Ownership is handled by idmapped read-only mounts.

### EROFS for runc in the first implementation

Rejected for now because it adds loop devices to the privileged path and their lifecycle to every recovery and teardown proof.

## Approved decisions

| #   | Decision                   | Approved choice                                                                                                   |
| --- | -------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| 1   | Rootfs compatibility       | Two releases after OCI images are stable, as a weaker mode with a deprecation event and no I8 claim               |
| 2   | Signature policy           | No implicit default; pinned keys and pinned keyless identities are both supported                                 |
| 3   | Provenance                 | Optional mechanism, required by the shipped reference production policy                                           |
| 4   | Offline time               | Certificate evaluated at proven signing time; revocation by deny-list or trust-root rotation for new admissions   |
| 5   | Initial budgets            | 1 GiB per layer, 2 GiB per image compressed, 8 GiB uncompressed, 200,000 files, 20 GiB store, 2 prepares          |
| 6   | Refusal classes            | New `Untrusted` (25) and `Capacity` (26)                                                                          |
| 7   | Archive metadata           | Reject every xattr and special file; an allow-list requires a later design                                        |
| 8   | runc representation        | Read-only bind mount of the unpacked directory; no EROFS for runc initially                                       |
| 9   | Firecracker disk           | EROFS                                                                                                             |
| 10  | UID and GID                | Idmapped mounts, typed `Unsupported` refusal without fallback; confirmed in SOG-3.02                              |
| 11  | Garbage collection         | Operator command and high-water trigger, both outside every call path                                             |
| 12  | Digest not found           | `Infrastructure` (23) with the distinct `DIGEST_NOT_FOUND` reason                                                 |
