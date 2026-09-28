---
layout: page
title: AI Agents
description: Already have an AI agent, in any framework? Keep it. Declare its security context, and Soglia makes it physical.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { withBase } from 'vitepress'
</script>

<div class="soglia-home soglia-arch soglia-agents">
  <section class="arch-hero">
    <div class="soglia-section-inner">
      <div class="soglia-kicker">Bring your own AI agent</div>
      <h1>Already have an AI agent? Keep it.</h1>
      <p>Whatever it is built with, Soglia runs it as it is. You do not rewrite the agent. <strong>You declare its security context, and Soglia makes it physical.</strong></p>
      <div class="arch-chips ag-frameworks"><span>LangChain</span><span>Google ADK</span><span>Microsoft Agent Framework</span><span>Strands</span><span>your own code</span></div>
    </div>
  </section>
  <section class="ag-same">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Use what you already use</div>
        <h2>Spot the difference. There isn't one.</h2>
      </div>
      <div class="ag-same__grid">
        <article>
          <div class="ag-same__label">Your agent today</div>
          <h3>Your framework. Your code. Your model.</h3>
          <p>Runs with whatever credentials and network the host happens to have.</p>
        </article>
        <article class="ag-same__soglia">
          <div class="ag-same__label">Your agent in Soglia</div>
          <h3>The same framework. The same code. The same model.</h3>
          <p>Runs in a fresh Execution, holding only a <span class="soglia-term" tabindex="0" data-tip="Virtual authority bound to one Execution. The agent uses it like any API token; outside that Execution it is worthless.">VPCA</span>, with no exit but the ones you declared.</p>
        </article>
      </div>
    </div>
  </section>
  <section class="ag-steps-sec">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">That is all it takes</div>
        <h2>Three steps. None of them touches your agent's code.</h2>
      </div>
      <ol class="ag-steps">
        <li>
          <div class="soglia-num">01</div>
          <h3>Package it</h3>
          <p>Ship your agent the way you already do. Nothing inside it changes.</p>
        </li>
        <li class="ag-steps__key">
          <div class="soglia-num">02</div>
          <h3>Declare its security context</h3>
          <p>What the agent may reach and do, and nothing else. Soglia turns that declaration into boundaries the kernel enforces, for every single call.</p>
        </li>
        <li>
          <div class="soglia-num">03</div>
          <h3>Call it</h3>
          <p>Every call gets its own fresh Execution, destroyed before you read the response.</p>
        </li>
      </ol>
    </div>
  </section>
  <section id="physics" class="soglia-principles arch-agents">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">The physics</div>
        <h2>Bring your own agent. Soglia brings the physics.</h2>
        <p class="arch-lead">Soglia is not another agent framework. The framework owns the agent's internals; Soglia owns the execution around it.</p>
      </div>
      <ol class="arch-pipeline">
        <li><div class="soglia-num">01</div><h3>Receive</h3><p>The call arrives with its PCA. Nothing runs until the Execution Context has validated its PIC and evaluated policy.</p></li>
        <li><div class="soglia-num">02</div><h3>Provision</h3><p>A fresh Execution is built for this invocation only: namespaces, cgroup, network namespace, read-only rootfs, network egress rules.</p></li>
        <li><div class="soglia-num">03</div><h3>Arm</h3><p>Ingress puts a <span class="soglia-term" tabindex="0" data-tip="Virtual authority bound to one Execution. The agent uses it like any API token; outside that Execution it is worthless.">VPCA</span> where the real PCA was.</p></li>
        <li><div class="soglia-num">04</div><h3>Run</h3><p>Your agent runs unchanged, and reaches the world only through Soglia.</p></li>
        <li><div class="soglia-num">05</div><h3>Destroy</h3><p>The whole Execution is torn down and verified gone before the response is released, or at once if an IFC label or a policy is violated.</p></li>
      </ol>
      <div class="arch-agents__body">
        <div class="arch-box" aria-label="The agent framework runs inside the Soglia physical boundary. Its only exit is Soglia Egress. The PCA, real credentials and signing keys stay outside.">
          <div class="arch-box__outside"><span>PCA</span><span>real credentials</span><span>signing keys</span><em>stay outside</em></div>
          <div class="arch-box__wall">
            <div class="arch-box__label">Soglia physical boundary · kernel-enforced</div>
            <div class="arch-box__agent">
              <div class="arch-box__agent-label">Your agent framework</div>
              <div class="arch-box__any">any framework, unchanged</div>
              <div class="arch-box__vpca">VPCA_E123 · bound to this Execution</div>
            </div>
          </div>
          <div class="arch-box__exit">only exit → Soglia Egress</div>
        </div>
        <div class="arch-claims">
          <p><strong>An AI agent never certifies its own continuation.</strong></p>
          <p><strong>Agent proposes. Boundary verifies. Soglia executes.</strong></p>
          <p><strong>AI intelligence may be probabilistic.</strong> External execution is admitted only through explicit boundaries.</p>
        </div>
      </div>
    </div>
  </section>
  <section class="arch-physical ag-vpca">
    <div class="soglia-section-inner ag-vpca__inner">
      <div>
        <div class="soglia-kicker">What your agent sees</div>
        <h2>A token that only works here.</h2>
        <p class="ag-vpca__lead">Your agent calls its tools exactly as it does today. The token it holds is a <span class="soglia-term" tabindex="0" data-tip="Virtual authority bound to one Execution. The agent uses it like any API token; outside that Execution it is worthless.">VPCA</span>, not the real thing.</p>
        <p class="ag-vpca__caption">On the way out, Soglia Egress swaps the VPCA for real authority. The agent never sees it.</p>
      </div>
      <aside class="ag-glossary" aria-label="Glossary">
        <div class="ag-glossary__item ag-glossary__item--key">
          <div class="ag-glossary__term">VPCA</div>
          <p>The virtual counterpart of a PCA, bound to exactly one Execution. Soglia Ingress puts it in place of the real authority, and Soglia Egress swaps it back at the boundary. Copied, stolen or replayed outside its Execution, it is worthless.</p>
        </div>
        <div class="ag-glossary__item">
          <div class="ag-glossary__term">PCA</div>
          <p>The real authority, obtained through Permguard. It stays with the Execution Context and never enters the Execution.</p>
        </div>
        <div class="ag-glossary__item">
          <div class="ag-glossary__term">Execution Context</div>
          <p>Where every security decision is taken, on the way in and on the way out: PIC validation and exchange, policy evaluation and IFC labels.</p>
        </div>
      </aside>
    </div>
  </section>
  <section class="arch-status">
    <div class="soglia-section-inner">
      <div class="arch-status__box">
        <div class="soglia-kicker">Status</div>
        <h3>What runs today</h3>
        <p>Soglia is under development. Phase 0 proves the execution loop and the mediated network path end to end: a fresh isolated Execution per call and egress only to declared destinations. Authority (PCA and VPCA), Permguard policies, PIC and IFC join the same security context in later phases. How agents are packaged and declared will be documented once that interface is final.</p>
        <div class="soglia-actions">
          <a class="soglia-btn soglia-btn--primary" :href="withBase('/how-it-works')">How it works</a>
          <a class="soglia-btn soglia-btn--ghost" href="https://github.com/permguard/soglia" target="_blank" rel="noopener noreferrer">View on GitHub</a>
        </div>
      </div>
    </div>
  </section>
</div>
