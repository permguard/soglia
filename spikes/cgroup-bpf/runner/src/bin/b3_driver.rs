// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! B3 entry point over the shared Candidate-A production qualification driver.

#[allow(dead_code)]
#[path = "b2_driver.rs"]
mod candidate_a;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init()
        .ok();
    if let Err(error) = candidate_a::run_b3().await {
        eprintln!("b3-driver: {error}");
        std::process::exit(20);
    }
}
