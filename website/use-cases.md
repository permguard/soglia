---
layout: page
title: Use cases
description: From an AI agent in the cloud to a control workload on a machine, Soglia runs every mission-critical process as a sandboxed invocation between two Execution Contexts.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Icons adapted from Lucide (https://lucide.dev), ISC License. -->

<script setup>
import { withBase } from 'vitepress'
</script>

<div class="soglia-home soglia-arch soglia-uses">
  <section class="arch-hero">
    <div class="soglia-section-inner">
      <div class="soglia-kicker">Use cases</div>
      <h1>Anything mission-critical. Anywhere it runs. One boundary.</h1>
      <p>An AI agent in the cloud or a control workload on a machine: Soglia runs it the same way, as a <strong>sandboxed invocation</strong> between two Execution Contexts, on the Linux servers and devices where it already lives.</p>
    </div>
  </section>
  <section class="soglia-principles uc-nodes">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">One boundary, any node</div>
        <h2>Wherever the kernel can build the sandbox, Soglia can run.</h2>
      </div>
      <div class="uc-unit" aria-label="An Execution Context on the way in, a sandboxed invocation inside a kernel-enforced boundary, an Execution Context on the way out">
        <span class="uc-unit__ctx">Execution Context</span>
        <span class="uc-path__kernel uc-unit__kernel"><span class="uc-unit__core">Sandboxed Invocation</span></span>
        <span class="uc-unit__ctx">Execution Context</span>
      </div>
      <div class="uc-fan" aria-hidden="true"><span>runs on any Linux node</span></div>
      <ul class="uc-hosts" aria-label="Nodes that can run it: a cloud virtual machine, a Kubernetes node, an on-premise server, a GPU server, an edge gateway, a machine or device">
        <li>Cloud VM</li>
        <li>Kubernetes node</li>
        <li>On-premise server</li>
        <li>GPU server</li>
        <li>Edge gateway</li>
        <li>Machine or device</li>
      </ul>
      <p class="uc-nodes__lead">The same sandboxed invocation, the same Execution Contexts, the same kernel-enforced boundary, on every node. See <a :href="withBase('/how-it-works')">How it works</a> for the full path of a call.</p>
    </div>
  </section>
  <section class="uc-kinds">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Two kinds of workload, one boundary</div>
        <h2>Whether it thinks or it controls, it runs the same way.</h2>
      </div>
      <div class="arch-layers__grid">
        <article>
          <h3>AI agents</h3>
          <p>Probabilistic code that plans, calls tools and acts. It may be wrong, manipulated or compromised, so it never holds real credentials and never reaches anything its context did not allow.</p>
        </article>
        <article>
          <h3>Mission-critical workloads</h3>
          <p>Deterministic processes whose effects matter: machine control, building automation, payments, operations. The same boundary makes every run isolated, bounded and gone when it ends.</p>
        </article>
      </div>
    </div>
  </section>
  <section class="uc-examples">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">In practice</div>
        <h2>Where it makes the difference.</h2>
      </div>
      <div class="uc-grid">
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M2 20a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8l-7 5V8l-7 5V4a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2Z"/><path d="M17 18h1M12 18h1M7 18h1"/></svg>
          <h3>Industrial IoT and machines</h3>
          <p>An AI agent on a machine's edge gateway reads sensor data and proposes maintenance or a new setpoint.</p>
          <dl><dt>Sandboxed invocation</dt><dd>one diagnosis, one proposal</dd><dt>Crosses the boundary</dt><dd>only the calls its context allows, never direct access to the controller</dd></dl>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 .709-1.528l7-5.999a2 2 0 0 1 2.582 0l7 5.999A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
          <h3>Building automation</h3>
          <p>An agent adjusts heating, access and lighting across a building from occupancy and energy prices.</p>
          <dl><dt>Sandboxed invocation</dt><dd>one decision cycle</dd><dt>Crosses the boundary</dt><dd>the building systems it was given, with authority that cannot grow</dd></dl>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2M20 14h2M15 13v2M9 13v2"/></svg>
          <h3>Robotics and operational systems</h3>
          <p>A planning agent turns a goal into a sequence of actions for a robot or an operational system.</p>
          <dl><dt>Sandboxed invocation</dt><dd>one plan, one run</dd><dt>Crosses the boundary</dt><dd>each action as a mediated effect, evaluated before it happens</dd></dl>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>
          <h3>Cloud and enterprise AI</h3>
          <p>A support or finance agent reads records, drafts answers and updates systems of record.</p>
          <dl><dt>Sandboxed invocation</dt><dd>one request, one customer's authority</dd><dt>Crosses the boundary</dt><dd>enterprise APIs, with a virtual token instead of real credentials</dd></dl>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/></svg>
          <h3>Local AI and GPU systems</h3>
          <p>On-premise models run next to sensitive data that must never leave the site.</p>
          <dl><dt>Sandboxed invocation</dt><dd>one inference task</dd><dt>Crosses the boundary</dt><dd>nothing that was not declared, so the data stays where it is</dd></dl>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <h3>Regulated operations</h3>
          <p>Payments, claims and approvals, where every effect must be justified and traceable.</p>
          <dl><dt>Sandboxed invocation</dt><dd>one transaction</dd><dt>Crosses the boundary</dt><dd>effects bound to the authority that started it, and nothing that outlives it</dd></dl>
        </article>
      </div>
    </div>
  </section>
  <section class="arch-status">
    <div class="soglia-section-inner">
      <div class="arch-status__box">
        <div class="soglia-kicker">Status</div>
        <h3>Scenarios, not certifications</h3>
        <p>These are the scenarios Soglia is designed for. Soglia is under development: Phase 0 proves the execution loop and the mediated network path end to end, and is not a production security release.</p>
        <div class="soglia-actions">
          <a class="soglia-btn soglia-btn--primary" :href="withBase('/how-it-works')">How it works</a>
          <a class="soglia-btn soglia-btn--ghost" :href="withBase('/agents')">AI Agents</a>
        </div>
      </div>
    </div>
  </section>
</div>
