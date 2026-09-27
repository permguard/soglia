// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Spike-only reader for the synthetic foreign program's ring buffer.

#![forbid(unsafe_code)]

use std::{
    env,
    io::Write as _,
    path::PathBuf,
    process, thread,
    time::{Duration, Instant},
};

use aya::maps::{Map, MapData, RingBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("FOREIGN TRACE ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    let pin = PathBuf::from(args.next().ok_or("missing pinned ring-buffer path")?);
    let seconds: u64 = args
        .next()
        .ok_or("missing observation duration")?
        .to_string_lossy()
        .parse()
        .map_err(|error| format!("parse duration: {error}"))?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".to_owned());
    }

    let map =
        MapData::from_pin(&pin).map_err(|error| format!("open {}: {error:#}", pin.display()))?;
    let map = Map::from_map_data(map).map_err(|error| format!("classify map: {error:#}"))?;
    let mut ring =
        RingBuf::try_from(map).map_err(|error| format!("open ring buffer: {error:#}"))?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(
        output,
        "reader_ready pin={} duration_seconds={seconds}",
        pin.display()
    )
    .map_err(|error| format!("write ready: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("flush ready: {error}"))?;

    let started = Instant::now();
    let mut count = 0_u64;
    while started.elapsed() < Duration::from_secs(seconds) {
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            count += 1;
            if bytes.len() == 24 {
                let seq = u64::from_ne_bytes(bytes[0..8].try_into().expect("fixed slice"));
                let who = u32::from_ne_bytes(bytes[8..12].try_into().expect("fixed slice"));
                let daddr = u32::from_ne_bytes(bytes[12..16].try_into().expect("fixed slice"));
                let dport = u32::from_ne_bytes(bytes[16..20].try_into().expect("fixed slice"));
                let rewritten = u32::from_ne_bytes(bytes[20..24].try_into().expect("fixed slice"));
                writeln!(
                    output,
                    "record count={count} seq={seq} who={who} daddr_raw={daddr} dport={dport} rewritten={rewritten} hex={}",
                    hex(bytes)
                )
                .map_err(|error| format!("write record: {error}"))?;
            } else {
                writeln!(
                    output,
                    "record count={count} unexpected_size={} hex={}",
                    bytes.len(),
                    hex(bytes)
                )
                .map_err(|error| format!("write malformed record: {error}"))?;
            }
            output
                .flush()
                .map_err(|error| format!("flush record: {error}"))?;
        }
        thread::sleep(Duration::from_millis(5));
    }
    writeln!(output, "reader_complete records={count}")
        .map_err(|error| format!("write completion: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("flush completion: {error}"))?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
