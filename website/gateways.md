---
layout: page
title: Gateways
description: Keep your gateway. Security was never a gateway feature, it is a layer beneath every boundary an execution crosses.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { withBase } from 'vitepress'
</script>

<div class="soglia-home soglia-arch soglia-gateways">
  <section class="arch-hero">
    <div class="soglia-section-inner">
      <div class="soglia-kicker">Gateways</div>
      <h1>Keep your gateway. Stop reinventing it for AI agents.</h1>
      <p>Every month brings a new kind of gateway, and each one promises security. But with AI agents the perimeter is gone: one execution crosses gateways, workers, async functions and edge nodes, composed at runtime. Security was never a gateway feature. It is <strong>a layer beneath every boundary an execution crosses</strong>.</p>
    </div>
  </section>
  <section class="soglia-principles gw-stack-sec">
    <div class="soglia-section-inner">
      <div class="soglia-section-head gw-stack-head">
        <div class="soglia-kicker">Where security lives</div>
        <h2>Security is not a feature. It is a layer.</h2>
        <p>Gateways decide where a call goes. The execution layer decides what an execution may do, at every boundary it crosses. Put security in a gateway, and every new gateway has to reinvent it, and every call that skips the gateway skips security with it. Put it beneath, and every boundary inherits it: the gateways, workers and functions you run today, and the ones that do not exist yet.</p>
      </div>
      <div class="gw-arch" aria-label="One execution crosses an API gateway, a worker, an async function, an AI agent, an MCP gateway and an edge node. One execution and security layer, run by Soglia with Permguard, sits beneath all of them, on top of the infrastructure.">
        <div class="gw-arch__caption"><span>No perimeter: the architecture is composed at runtime</span><span class="gw-arch__one">one execution crosses them all</span></div>
        <div class="gw-arch__row" aria-hidden="true">
          <span class="gw-bnd">API gateway</span>
          <span class="gw-bnd">Worker</span>
          <span class="gw-bnd">Async function</span>
          <span class="gw-bnd">AI agent</span>
          <span class="gw-bnd">MCP gateway</span>
          <span class="gw-bnd">Edge node</span>
        </div>
        <div class="pv-layer pv-layer--exec gw-arch__layer">
          <div class="pv-layer__owner">Soglia with Permguard · beneath every boundary</div>
          <div class="pv-layer__title">Execution &amp; security</div>
          <div class="arch-chips"><span>execution boundaries</span><span>authority</span><span>policy evaluation</span><span>IFC labels</span><span>virtual credentials</span><span>lifecycle</span></div>
          <div class="gw-layer__role">decides what an execution may do, wherever it runs</div>
        </div>
        <div class="gw-seam gw-seam--plain" aria-hidden="true"><span>runs on it</span></div>
        <div class="pv-layer">
          <div class="pv-layer__owner">Your provider</div>
          <div class="pv-layer__title">Infrastructure</div>
          <div class="arch-chips"><span>cloud</span><span>virtual machines</span><span>Kubernetes</span><span>edge devices</span><span>network</span></div>
          <div class="gw-layer__role gw-layer__role--muted">the one you already run on, from a public cloud to a single rack: see <a :href="withBase('/providers')">Cloud &amp; Infrastructure</a></div>
        </div>
      </div>
    </div>
  </section>
  <section class="gw-types">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Every kind of gateway</div>
        <h2>Every gateway guards a path. None of them guards the execution.</h2>
      </div>
      <div class="pv-table-wrap">
        <table class="pv-table">
          <thead><tr><th>Gateway</th><th>The path it guards</th><th>What it cannot see</th></tr></thead>
          <tbody>
            <tr><td>API gateway</td><td>Calls entering from outside to your services</td><td>What the execution does once the call is inside</td></tr>
            <tr><td>AI gateway</td><td>Calls to models: routing, fallback, quotas, costs</td><td>Which execution sent the prompt, and under which authority</td></tr>
            <tr><td>MCP gateway</td><td>Calls to tools</td><td>Whether the execution calling the tool may do so</td></tr>
            <tr><td>A2A gateway</td><td>Calls between agents, when they pass through a central point</td><td>The calls that go directly from one agent to another</td></tr>
          </tbody>
        </table>
        <div class="tbl-foot">Each one sees the calls on its own path. An execution crosses many paths, and some of them cross no gateway at all.</div>
      </div>
    </div>
  </section>
  <section class="soglia-principles gw-slice">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Outside the execution</div>
        <h2>A gateway sees a slice of the execution. It is asked to secure all of it.</h2>
      </div>
      <div class="gw-slice__view" aria-label="An execution runs through six steps. The gateway sees only the first. The other five are left to the workers, queues and agents behind it.">
        <div class="gw-slice__steps" aria-hidden="true">
          <span class="gw-slice__seen">enters</span>
          <span>worker</span>
          <span>queue</span>
          <span>agent</span>
          <span>tool</span>
          <span>next agent</span>
        </div>
        <div class="gw-slice__marks" aria-hidden="true">
          <span class="gw-slice__mark gw-slice__mark--seen">what the gateway sees</span>
          <span class="gw-slice__mark gw-slice__mark--rest">left to whoever comes next: "check the rest yourselves"</span>
        </div>
      </div>
      <div class="pv-cards">
        <article>
          <div class="soglia-num">01</div>
          <h3>It stands outside</h3>
          <p>A gateway is a checkpoint on a path, not part of the execution. It does not run with it, carry its authority or follow it to the next step.</p>
        </article>
        <article>
          <div class="soglia-num">02</div>
          <h3>It decides on a slice</h3>
          <p>It sees the calls that cross it, at the moment they cross. A decision taken on part of the state cannot hold a property that depends on the rest of it.</p>
        </article>
        <article>
          <div class="soglia-num">03</div>
          <h3>It hands off the rest</h3>
          <p>Past the gateway, every worker, queue consumer and agent is trusted to carry the context and check what is left. Security becomes an assumption.</p>
        </article>
      </div>
      <blockquote class="arch-quote">A gateway can guard a door. <strong>An execution has no walls.</strong></blockquote>
    </div>
  </section>
  <section class="gw-shift">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">From centralized to distributed</div>
        <h2>From one checkpoint at the edge to a boundary around every execution.</h2>
      </div>
      <div class="gw-model">
        <div class="gw-model__row">
          <div class="gw-model__text">
            <h3>Centralized: the gateway sees one hop</h3>
            <p>The call that enters is checked. Everything after it, agent to agent, agent to tool, happens out of the gateway's sight.</p>
          </div>
          <div class="gw-chain" aria-label="A call passes the gateway, then Agent A calls Agent B, which calls a tool. The gateway sees only the first hop.">
            <span class="gw-hop">Call</span><i class="gw-arrow"></i>
            <span class="gw-hop gw-hop--gate">Gateway</span><i class="gw-arrow"></i>
            <span class="gw-hop gw-hop--dim">Agent A</span><i class="gw-arrow gw-arrow--dim"></i>
            <span class="gw-hop gw-hop--dim">Agent B</span><i class="gw-arrow gw-arrow--dim"></i>
            <span class="gw-hop gw-hop--dim">Tool</span>
            <div class="gw-span gw-span--unseen"><span>beyond the gateway: unseen</span></div>
          </div>
        </div>
        <div class="gw-model__row">
          <div class="gw-model__text">
            <h3>Distributed: every execution is bounded</h3>
            <p>The gateway still guards the edge. Every execution runs inside its own boundary, and the authority it received travels with it to the next one.</p>
          </div>
          <div class="gw-chain" aria-label="The same chain: the gateway stays, and Agent A, Agent B and the tool call each run inside a bounded execution. Authority travels with every call and never expands.">
            <span class="gw-hop">Call</span><i class="gw-arrow"></i>
            <span class="gw-hop gw-hop--gate">Gateway</span><i class="gw-arrow"></i>
            <span class="gw-hop gw-hop--exec">Agent A</span><i class="gw-arrow"></i>
            <span class="gw-hop gw-hop--exec">Agent B</span><i class="gw-arrow"></i>
            <span class="gw-hop gw-hop--exec">Tool</span>
            <div class="gw-span gw-span--authority"><span>authority travels with every call, and never expands</span></div>
          </div>
        </div>
      </div>
    </div>
  </section>
  <section class="soglia-principles gw-cases">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Whatever the path</div>
        <h2>Gateway or no gateway, the same boundary.</h2>
      </div>
      <div class="pv-cards">
        <article>
          <div class="soglia-num">01</div>
          <h3>Through a gateway</h3>
          <p>A call arrives through your API gateway. The gateway does its job, and the boundary applies the moment the call reaches an execution.</p>
        </article>
        <article>
          <div class="soglia-num">02</div>
          <h3>Agent to agent</h3>
          <p>One execution calls another, and no gateway is in between. The boundary applies on both sides, and the authority carried across can only narrow.</p>
        </article>
        <article>
          <div class="soglia-num">03</div>
          <h3>Out to a model or a tool</h3>
          <p>Through an AI gateway, an MCP gateway or directly: what leaves the execution, with which credentials and under which labels, is decided on the way out.</p>
        </article>
      </div>
      <blockquote class="arch-quote">Gateways route calls. <strong>Executions carry authority.</strong></blockquote>
    </div>
  </section>
  <section class="pv-split">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">What you keep, what you gain</div>
        <h2>Nothing to rebuild. Nothing to duplicate. Only added.</h2>
        <p class="kp-lead">Your gateways keep doing their job, and now stand on Soglia. Everything they do today stays; the right column only grows.</p>
      </div>
      <div class="kp-table-wrap">
        <table class="kp-table" aria-label="What your gateways keep, and what Soglia adds beneath them">
          <thead><tr><th>Capability</th><th>Your gateways today</th><th>With Soglia beneath</th></tr></thead>
          <tbody>
            <tr><td>Routing and load balancing</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr><td>Model routing, fallback and caching</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr><td>Quotas, rate limits and cost control</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr><td>Authentication at the edge</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr><td>Observability of the traffic that crosses them</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr><td>Content filters on prompts and responses</td><td><span class="kp-keep">yours</span></td><td><span class="kp-keep">yours, unchanged</span></td></tr>
            <tr class="kp-added kp-first-added"><td>A boundary around every execution</td><td><span class="kp-none">—</span></td><td><span class="kp-add">Soglia</span></td></tr>
            <tr class="kp-added"><td>Authority carried from one execution to the next</td><td><span class="kp-none">—</span></td><td><span class="kp-add">Soglia, with Permguard</span></td></tr>
            <tr class="kp-added"><td>Policy evaluation and IFC labels on every call in and out</td><td><span class="kp-none">—</span></td><td><span class="kp-add">Soglia, with Permguard</span></td></tr>
            <tr class="kp-added"><td>Real credentials that never reach the workload</td><td><span class="kp-none">—</span></td><td><span class="kp-add">Soglia</span></td></tr>
            <tr class="kp-added"><td>Verified teardown of every execution</td><td><span class="kp-none">—</span></td><td><span class="kp-add">Soglia</span></td></tr>
          </tbody>
        </table>
        <div class="tbl-foot kp-sum"><span>Kept: <strong>6</strong></span><span class="kp-sum__lost">Lost: <strong>none</strong></span><span>Added: <strong>5</strong></span></div>
      </div>
    </div>
  </section>
  <section class="arch-status pv-status">
    <div class="soglia-section-inner">
      <div class="arch-status__box">
        <div class="soglia-kicker">Status</div>
        <h3>A layer, not another gateway</h3>
        <p>Soglia is under development: Phase 0 proves the execution loop and the mediated network path end to end, and is not a production security release. This page describes where Soglia is designed to sit relative to the gateways you run, and where each responsibility lives.</p>
        <div class="soglia-actions">
          <a class="soglia-btn soglia-btn--primary" :href="withBase('/how-it-works')">How it works</a>
          <a class="soglia-btn soglia-btn--ghost" href="https://github.com/permguard/soglia" target="_blank" rel="noopener noreferrer">View on GitHub</a>
        </div>
      </div>
    </div>
  </section>
</div>
