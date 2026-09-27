// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Name resolution for the egress proxy.
//!
//! The proxy resolves each destination exactly once per attempt and connects only to addresses it
//! validated from that one answer. The resolver is a seam so tests can serve answers a real resolver
//! would only give an attacker.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;

/// A boxed resolution in progress.
pub type Resolution<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Resolves a host name to every address it has.
pub trait Resolver: Send + Sync {
    /// Every A and AAAA answer for `name`, in the order the resolver returned them.
    fn resolve<'a>(&'a self, name: &'a str) -> Resolution<'a>;
}

/// The host's resolver.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, name: &'a str) -> Resolution<'a> {
        Box::pin(async move {
            // The port is irrelevant to the answer; the caller pairs addresses with its own port.
            let answers = tokio::net::lookup_host((name, 0)).await?;
            Ok(answers.map(|socket| socket.ip()).collect())
        })
    }
}

#[cfg(test)]
pub(crate) mod fixed {
    use super::*;
    use std::collections::HashMap;

    /// A resolver with canned answers.
    #[derive(Debug, Default, Clone)]
    pub(crate) struct FixedResolver(pub(crate) HashMap<String, Vec<IpAddr>>);

    impl FixedResolver {
        pub(crate) fn with(mut self, name: &str, addresses: &[&str]) -> Self {
            self.0.insert(
                name.to_owned(),
                addresses
                    .iter()
                    .map(|address| address.parse().unwrap())
                    .collect(),
            );
            self
        }
    }

    impl Resolver for FixedResolver {
        fn resolve<'a>(&'a self, name: &'a str) -> Resolution<'a> {
            Box::pin(async move {
                self.0
                    .get(name)
                    .cloned()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such name"))
            })
        }
    }
}
