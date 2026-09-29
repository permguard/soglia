---
layout: page
title: Cloud & Infrastructure Providers
description: Soglia runs on the compute and network you already provide, and adds the next layer of security, the one your network cannot see.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { withBase } from 'vitepress'
</script>

<div class="soglia-home soglia-arch soglia-providers">
  <section class="arch-hero">
    <div class="soglia-section-inner">
      <div class="soglia-kicker">Cloud &amp; Infrastructure Providers</div>
      <h1>We run on your infrastructure. We do not compete with it.</h1>
      <p>Public cloud, hyperscale or a single rack of servers: Soglia runs on the compute and the network you already provide, and adds the next layer of security, <strong>the one your network cannot see</strong>: what each execution does inside the host.</p>
    </div>
  </section>
  <section class="soglia-principles pv-stack-sec">
    <div class="soglia-section-inner pv-stack-sec__inner">
      <div>
        <div class="soglia-kicker">Two layers, two owners</div>
        <h2>Up to the host, security is yours. Inside the host, it is the execution's.</h2>
        <p>Your network sees connections between hosts. It cannot see which execution inside a host opened them, under which authority, or what that execution is allowed to do next. That is where Soglia starts, and where your responsibility can stay exactly as it is.</p>
      </div>
      <div class="pv-stack" aria-label="Execution layer, run by Soglia inside the host, above the infrastructure layer, run by the provider up to the host">
        <div class="pv-layer pv-layer--exec">
          <div class="pv-layer__owner">Soglia · inside the host</div>
          <div class="pv-layer__title">Execution layer</div>
          <div class="arch-chips"><span>execution boundaries</span><span>authority</span><span>policy evaluation</span><span>IFC labels</span><span>virtual credentials</span><span>lifecycle</span></div>
        </div>
        <div class="pv-host" aria-hidden="true"><span>the host</span></div>
        <div class="pv-layer pv-layer--infra">
          <div class="pv-layer__owner">You · up to the host</div>
          <div class="pv-layer__title">Infrastructure layer</div>
          <div class="arch-chips"><span>compute</span><span>network</span><span>routing</span><span>network ACLs</span><span>segmentation</span><span>encryption in transit</span></div>
        </div>
      </div>
    </div>
  </section>
  <section class="pv-keep">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">A clean split</div>
        <h2>Let the network do what it does best.</h2>
      </div>
      <div class="pv-cards">
        <article>
          <div class="soglia-num">01</div>
          <h3>Keep your network controls</h3>
          <p>Traffic, network ACLs, segmentation and encryption stay where they belong. They decide who can connect to what, and Soglia relies on them.</p>
        </article>
        <article>
          <div class="soglia-num">02</div>
          <h3>Keep application logic out of the network</h3>
          <p>A network rule cannot see inside an execution. Asking it to decide what an application may do turns every rule into a guess.</p>
        </article>
        <article>
          <div class="soglia-num">03</div>
          <h3>Let execution boundaries sit above</h3>
          <p>Soglia builds a boundary around every execution, on every node, running on top of your network instead of replacing any part of it.</p>
        </article>
      </div>
      <blockquote class="arch-quote pv-quote">Keep your network controls. <strong>Stop relying on them to decide what an execution may do.</strong></blockquote>
    </div>
  </section>
  <section class="pv-dist">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Seen from above</div>
        <h2>Executions are distributed. Your network carries them. Soglia bounds them.</h2>
      </div>
      <div class="pv-fabric" aria-label="Three nodes, each running several bounded executions, connected by the provider's network. Authority continues between executions across nodes.">
        <div class="pv-nodes">
          <div class="pv-node"><div class="pv-node__name">Node A</div><div class="pv-execs"><span>Execution</span><span>Execution</span></div></div>
          <div class="pv-node"><div class="pv-node__name">Node B</div><div class="pv-execs"><span>Execution</span><span>Execution</span><span>Execution</span></div></div>
          <div class="pv-node"><div class="pv-node__name">Node C</div><div class="pv-execs"><span>Execution</span></div></div>
        </div>
        <div class="pv-continuity"><span>authority continues between executions, across nodes, and never expands</span></div>
        <div class="pv-net"><strong>Your network</strong><span>routing · network ACLs · segmentation · encryption in transit</span></div>
      </div>
    </div>
  </section>
  <section class="soglia-principles pv-opp">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">An opportunity, not a threat</div>
        <h2>The same infrastructure, one layer more valuable.</h2>
      </div>
      <div class="pv-cards">
        <article>
          <h3>No overlap</h3>
          <p>Soglia does not replace your compute, your network, your hypervisor or the isolation you already offer. It uses them.</p>
        </article>
        <article>
          <h3>A secure execution tier</h3>
          <p>Offer your customers a place where AI agents and mission-critical workloads run with kernel-enforced execution boundaries, on the capacity you already sell.</p>
        </article>
        <article>
          <h3>Workloads you could not host before</h3>
          <p>Probabilistic agents and regulated processes that need proof of what they may do, not only of where they run, become workloads you can take on.</p>
        </article>
      </div>
    </div>
  </section>
  <section class="pv-split">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">What you keep, what you gain</div>
        <h2>Nothing is taken from you. Something is added above.</h2>
        <p class="kp-lead">Soglia stands on the infrastructure you run, and competes with none of it. Everything you offer today stays; the right column only grows.</p>
      </div>
      <div class="kp-table-wrap">
        <table class="kp-table" aria-label="What the infrastructure keeps, and what Soglia adds on top of it">
          <thead><tr><th>Capability</th><th>Your infrastructure today</th><th>With Soglia on top</th></tr></thead>
          <tbody>
            <tr><td>Physical and virtual network, routing</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr><td>Network ACLs, segmentation, firewalls</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr><td>Compute, hypervisor, host operating system</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr><td>The isolation you offer between tenants</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr><td>Encryption in transit between nodes</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr class="kp-added kp-first-added"><td>A boundary around every execution inside the host</td><td><span class="kp-none">—</span></td><td><span class="kp-add">Soglia</span></td></tr>
            <tr class="kp-added"><td>Authority, policy evaluation and IFC labels per execution</td><td><span class="kp-none">—</span></td><td><span class="kp-add">Soglia, with Permguard</span></td></tr>
            <tr class="kp-added"><td>Real credentials that never reach the workload</td><td><span class="kp-none">—</span></td><td><span class="kp-add">Soglia</span></td></tr>
            <tr class="kp-added"><td>Execution lifecycle and verified teardown</td><td><span class="kp-none">—</span></td><td><span class="kp-add">Soglia</span></td></tr>
          </tbody>
        </table>
        <div class="tbl-foot kp-sum"><span>Kept: <strong>5</strong></span><span class="kp-sum__lost">Lost: <strong>none</strong></span><span>Added: <strong>4</strong></span></div>
      </div>
    </div>
  </section>
  <section class="arch-status pv-status">
    <div class="soglia-section-inner">
      <div class="arch-status__box">
        <div class="soglia-kicker">Status</div>
        <h3>A model to build together</h3>
        <p>Soglia is under development: Phase 0 proves the execution loop and the mediated network path end to end, and is not a production security release. This page describes how Soglia is designed to sit on top of an infrastructure provider, and where each responsibility lives.</p>
        <div class="soglia-actions">
          <a class="soglia-btn soglia-btn--primary" :href="withBase('/how-it-works')">How it works</a>
          <a class="soglia-btn soglia-btn--ghost" href="https://github.com/permguard/soglia" target="_blank" rel="noopener noreferrer">View on GitHub</a>
        </div>
      </div>
    </div>
  </section>
</div>
