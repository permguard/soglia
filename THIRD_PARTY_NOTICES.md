<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-Party Notices

Soglia is distributed under the Apache License, Version 2.0.
It links the third-party packages listed below, each under its own licence.

This file is generated from the resolved dependency graph — the transitive closure at the exact versions a Linux build receives — and is checked in CI.
Do not edit it by hand: run `task notices` (or `make notices`) instead.

Development dependencies are excluded: a notice covers what is distributed, and a test harness is not.
Build dependencies are included, because the terms of a build script travel with the artifact it helped produce.

Licences are the SPDX expressions each package declares.
Where a package declares none, the entry says so and its repository is the authority.

## Packages

93 packages.

| Package                 | Version      | Licence                                             | Source                                                |
| ----------------------- | ------------ | --------------------------------------------------- | ----------------------------------------------------- |
| `anstream`              | 1.0.0        | MIT OR Apache-2.0                                   | <https://github.com/rust-cli/anstyle.git>             |
| `anstyle`               | 1.0.14       | MIT OR Apache-2.0                                   | <https://github.com/rust-cli/anstyle.git>             |
| `anstyle-parse`         | 1.0.0        | MIT OR Apache-2.0                                   | <https://github.com/rust-cli/anstyle.git>             |
| `anstyle-query`         | 1.1.5        | MIT OR Apache-2.0                                   | <https://github.com/rust-cli/anstyle.git>             |
| `assert_matches`        | 1.5.0        | MIT/Apache-2.0                                      | <https://github.com/murarth/assert_matches>           |
| `atomic-waker`          | 1.1.2        | Apache-2.0 OR MIT                                   | <https://github.com/smol-rs/atomic-waker>             |
| `aya`                   | 0.14.0       | MIT OR Apache-2.0                                   | <https://github.com/aya-rs/aya>                       |
| `aya-obj`               | 0.3.0        | MIT OR Apache-2.0                                   | <https://github.com/aya-rs/aya>                       |
| `bitflags`              | 2.13.2       | MIT OR Apache-2.0                                   | <https://github.com/bitflags/bitflags>                |
| `block-buffer`          | 0.10.4       | MIT OR Apache-2.0                                   | <https://github.com/RustCrypto/utils>                 |
| `bytes`                 | 1.12.1       | MIT                                                 | <https://github.com/tokio-rs/bytes>                   |
| `cc`                    | 1.5.1        | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/cc-rs>                  |
| `cfg-if`                | 1.0.5        | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/cfg-if>                 |
| `cfg_aliases`           | 0.2.2        | MIT                                                 | <https://github.com/katharostech/cfg_aliases>         |
| `clap`                  | 4.6.7        | MIT OR Apache-2.0                                   | <https://github.com/clap-rs/clap>                     |
| `clap_builder`          | 4.6.7        | MIT OR Apache-2.0                                   | <https://github.com/clap-rs/clap>                     |
| `clap_derive`           | 4.6.7        | MIT OR Apache-2.0                                   | <https://github.com/clap-rs/clap>                     |
| `clap_lex`              | 1.1.1        | MIT OR Apache-2.0                                   | <https://github.com/clap-rs/clap>                     |
| `colorchoice`           | 1.0.5        | MIT OR Apache-2.0                                   | <https://github.com/rust-cli/anstyle.git>             |
| `cpufeatures`           | 0.2.17       | MIT OR Apache-2.0                                   | <https://github.com/RustCrypto/utils>                 |
| `crc32fast`             | 1.5.2        | MIT OR Apache-2.0                                   | <https://github.com/srijs/rust-crc32fast>             |
| `crypto-common`         | 0.1.7        | MIT OR Apache-2.0                                   | <https://github.com/RustCrypto/traits>                |
| `digest`                | 0.10.7       | MIT OR Apache-2.0                                   | <https://github.com/RustCrypto/traits>                |
| `equivalent`            | 1.0.2        | Apache-2.0 OR MIT                                   | <https://github.com/indexmap-rs/equivalent>           |
| `errno`                 | 0.3.14       | MIT OR Apache-2.0                                   | <https://github.com/lambda-fairy/rust-errno>          |
| `find-msvc-tools`       | 0.1.14       | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/cc-rs>                  |
| `foldhash`              | 0.2.0        | Zlib                                                | <https://github.com/orlp/foldhash>                    |
| `futures-channel`       | 0.3.34       | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/futures-rs>             |
| `futures-core`          | 0.3.34       | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/futures-rs>             |
| `generic-array`         | 0.14.7       | MIT                                                 | <https://github.com/fizyk20/generic-array.git>        |
| `hashbrown`             | 0.17.1       | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/hashbrown>              |
| `heck`                  | 0.5.0        | MIT OR Apache-2.0                                   | <https://github.com/withoutboats/heck>                |
| `http`                  | 1.5.0        | MIT OR Apache-2.0                                   | <https://github.com/hyperium/http>                    |
| `http-body`             | 1.1.0        | MIT                                                 | <https://github.com/hyperium/http-body>               |
| `http-body-util`        | 0.1.5        | MIT                                                 | <https://github.com/hyperium/http-body>               |
| `httparse`              | 1.10.1       | MIT OR Apache-2.0                                   | <https://github.com/seanmonstar/httparse>             |
| `httpdate`              | 1.0.3        | MIT OR Apache-2.0                                   | <https://github.com/pyfisch/httpdate>                 |
| `hyper`                 | 1.11.1       | MIT                                                 | <https://github.com/hyperium/hyper>                   |
| `hyper-util`            | 0.1.21       | MIT                                                 | <https://github.com/hyperium/hyper-util>              |
| `indexmap`              | 2.14.2       | Apache-2.0 OR MIT                                   | <https://github.com/indexmap-rs/indexmap>             |
| `is_terminal_polyfill`  | 1.70.2       | MIT OR Apache-2.0                                   | <https://github.com/polyfill-rs/is_terminal_polyfill> |
| `itoa`                  | 1.0.18       | MIT OR Apache-2.0                                   | <https://github.com/dtolnay/itoa>                     |
| `lazy_static`           | 1.5.0        | MIT OR Apache-2.0                                   | <https://github.com/rust-lang-nursery/lazy-static.rs> |
| `libbpf-rs`             | 0.27.2       | LGPL-2.1-only OR BSD-2-Clause                       | <https://github.com/libbpf/libbpf-rs>                 |
| `libbpf-sys`            | 1.7.0+v1.7.0 | BSD-2-Clause                                        | <https://github.com/libbpf/libbpf-sys>                |
| `libc`                  | 0.2.189      | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/libc>                   |
| `linux-raw-sys`         | 0.12.1       | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | <https://github.com/sunfishcode/linux-raw-sys>        |
| `log`                   | 0.4.34       | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/log>                    |
| `memchr`                | 2.8.3        | Unlicense OR MIT                                    | <https://github.com/BurntSushi/memchr>                |
| `mio`                   | 1.2.3        | MIT                                                 | <https://github.com/tokio-rs/mio>                     |
| `nix`                   | 0.31.3       | MIT                                                 | <https://github.com/nix-rust/nix>                     |
| `nu-ansi-term`          | 0.50.3       | MIT                                                 | <https://github.com/nushell/nu-ansi-term>             |
| `object`                | 0.39.1       | Apache-2.0 OR MIT                                   | <https://github.com/gimli-rs/object>                  |
| `once_cell`             | 1.21.4       | MIT OR Apache-2.0                                   | <https://github.com/matklad/once_cell>                |
| `pin-project-lite`      | 0.2.17       | Apache-2.0 OR MIT                                   | <https://github.com/taiki-e/pin-project-lite>         |
| `pkg-config`            | 0.3.34       | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/pkg-config-rs>          |
| `proc-macro2`           | 1.0.107      | MIT OR Apache-2.0                                   | <https://github.com/dtolnay/proc-macro2>              |
| `quote`                 | 1.0.47       | MIT OR Apache-2.0                                   | <https://github.com/dtolnay/quote>                    |
| `rustix`                | 1.1.5        | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | <https://github.com/bytecodealliance/rustix>          |
| `ryu`                   | 1.0.23       | Apache-2.0 OR BSL-1.0                               | <https://github.com/dtolnay/ryu>                      |
| `scopeguard`            | 1.2.0        | MIT OR Apache-2.0                                   | <https://github.com/bluss/scopeguard>                 |
| `serde`                 | 1.0.229      | MIT OR Apache-2.0                                   | <https://github.com/serde-rs/serde>                   |
| `serde_core`            | 1.0.229      | MIT OR Apache-2.0                                   | <https://github.com/serde-rs/serde>                   |
| `serde_derive`          | 1.0.229      | MIT OR Apache-2.0                                   | <https://github.com/serde-rs/serde>                   |
| `serde_json`            | 1.0.151      | MIT OR Apache-2.0                                   | <https://github.com/serde-rs/json>                    |
| `serde_norway`          | 0.9.42       | MIT OR Apache-2.0                                   | <https://github.com/cafkafk/serde-yaml>               |
| `sha2`                  | 0.10.9       | MIT OR Apache-2.0                                   | <https://github.com/RustCrypto/hashes>                |
| `sharded-slab`          | 0.1.7        | MIT                                                 | <https://github.com/hawkw/sharded-slab>               |
| `shlex`                 | 2.0.1        | MIT OR Apache-2.0                                   | <https://github.com/comex/rust-shlex>                 |
| `signal-hook-registry`  | 1.4.8        | MIT OR Apache-2.0                                   | <https://github.com/vorner/signal-hook>               |
| `smallvec`              | 1.16.2       | MIT OR Apache-2.0                                   | <https://github.com/servo/rust-smallvec>              |
| `socket2`               | 0.6.5        | MIT OR Apache-2.0                                   | <https://github.com/rust-lang/socket2>                |
| `strsim`                | 0.11.1       | MIT                                                 | <https://github.com/rapidfuzz/strsim-rs>              |
| `syn`                   | 2.0.119      | MIT OR Apache-2.0                                   | <https://github.com/dtolnay/syn>                      |
| `syn`                   | 3.0.6        | MIT OR Apache-2.0                                   | <https://github.com/dtolnay/syn>                      |
| `thiserror`             | 2.0.21       | MIT OR Apache-2.0                                   | <https://github.com/dtolnay/thiserror>                |
| `thiserror-impl`        | 2.0.21       | MIT OR Apache-2.0                                   | <https://github.com/dtolnay/thiserror>                |
| `thread_local`          | 1.1.10       | MIT OR Apache-2.0                                   | <https://github.com/Amanieu/thread_local-rs>          |
| `tokio`                 | 1.53.1       | MIT                                                 | <https://github.com/tokio-rs/tokio>                   |
| `tokio-macros`          | 2.7.2        | MIT                                                 | <https://github.com/tokio-rs/tokio>                   |
| `tracing`               | 0.1.44       | MIT                                                 | <https://github.com/tokio-rs/tracing>                 |
| `tracing-attributes`    | 0.1.31       | MIT                                                 | <https://github.com/tokio-rs/tracing>                 |
| `tracing-core`          | 0.1.36       | MIT                                                 | <https://github.com/tokio-rs/tracing>                 |
| `tracing-subscriber`    | 0.3.23       | MIT                                                 | <https://github.com/tokio-rs/tracing>                 |
| `try-lock`              | 0.2.5        | MIT                                                 | <https://github.com/seanmonstar/try-lock>             |
| `typenum`               | 1.20.1       | MIT OR Apache-2.0                                   | <https://github.com/paholg/typenum>                   |
| `unicode-ident`         | 1.0.26       | (MIT OR Apache-2.0) AND Unicode-3.0                 | <https://github.com/dtolnay/unicode-ident>            |
| `unsafe-libyaml-norway` | 0.2.15       | MIT                                                 | <https://github.com/cafkafk/unsafe-libyaml-norway>    |
| `utf8parse`             | 0.2.2        | Apache-2.0 OR MIT                                   | <https://github.com/alacritty/vte>                    |
| `version_check`         | 0.9.5        | MIT/Apache-2.0                                      | <https://github.com/SergioBenitez/version_check>      |
| `vsprintf`              | 2.0.0        | MIT                                                 | <https://github.com/dylanmckay/vsprintf>              |
| `want`                  | 0.3.1        | MIT                                                 | <https://github.com/seanmonstar/want>                 |
| `zmij`                  | 1.0.23       | MIT                                                 | <https://github.com/dtolnay/zmij>                     |

## Packages without a declared licence

Every package above declares an SPDX licence expression.

## Full licence texts

The full text of the Apache License 2.0 is in [LICENSE](LICENSE).
The texts of the other licences named above are published by their respective projects at the sources listed, and are reproduced in the vendored copy of each package in the Cargo registry cache.

For licence questions, contact <opensource@permguard.com>.
