---
layout: page
title: How it works
description: Security becomes physical. How Soglia turns every invocation into a fresh, isolated Execution that carries its own authority and is destroyed when it ends.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { onMounted, onBeforeUnmount, ref, watch } from 'vue'
import { withBase } from 'vitepress'

const zoomed = ref(false)
const close = () => { zoomed.value = false }
const onKey = (event) => { if (event.key === 'Escape') close() }
watch(zoomed, (open) => { document.documentElement.style.overflow = open ? 'hidden' : '' })
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey)
  document.documentElement.style.overflow = ''
})
</script>

<div class="soglia-home soglia-arch">
  <section class="arch-hero">
    <div class="soglia-section-inner">
      <div class="soglia-kicker">How it works</div>
      <h1>Security becomes physical.</h1>
      <p>Soglia changes the unit of security from the <strong>service</strong> to the <strong>execution occurrence</strong>, and enforces it with the kernel, not with the code running inside.</p>
      <div class="arch-equation" aria-label="One request equals one authority context equals one fresh isolated Execution">
        <span>one request</span><b>=</b><span>one authority context</span><b>=</b><span class="arch-equation__soglia">one fresh isolated Execution</span>
      </div>
    </div>
  </section>
  <section class="arch-missing">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">The missing security boundary</div>
        <h2>Deciding authority is not enough.</h2>
      </div>
      <div class="arch-ladder">
        <article>
          <div class="soglia-num">01</div>
          <h3>Authorization</h3>
          <p>Decides <strong>who may do what</strong>.</p>
        </article>
        <article>
          <div class="soglia-num">02</div>
          <h3>PIC</h3>
          <p>Proves <strong>which causal execution</strong> the authority belongs to, and whether it may continue to the next step.</p>
        </article>
        <article class="arch-ladder__soglia">
          <div class="soglia-num">03</div>
          <h3>Soglia</h3>
          <p>Confines <strong>the code that actually exercises that authority</strong>: the one boundary that was still left.</p>
        </article>
      </div>
    </div>
  </section>
  <section class="soglia-principles arch-leap">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Not another sandbox</div>
        <h2>A sandbox confines code. Soglia confines an execution, and the authority it carries.</h2>
      </div>
      <div class="arch-compare">
        <article>
          <h3>A traditional sandbox</h3>
          <div class="arch-mini" aria-hidden="true">
            <div class="arch-mini__reqs"><span>request A</span><span>request B</span><span>request C</span></div>
            <div class="arch-mini__arrow">→</div>
            <div class="arch-mini__proc">one long-lived process</div>
            <div class="arch-mini__arrow">→</div>
            <div class="arch-mini__shared">shared credentials, globals, caches, connections</div>
          </div>
          <ul>
            <li>Isolates a workload from the host, then feeds many requests through it.</li>
            <li>Credentials, caches, connections and mutable state accumulate as <strong>ambient authority</strong>.</li>
            <li>Security depends on every function always receiving, preserving and using the correct context.</li>
            <li>Too weak for untrusted or probabilistic AI code.</li>
          </ul>
        </article>
        <article class="arch-compare__soglia">
          <h3>Soglia</h3>
          <div class="arch-mini" aria-hidden="true">
            <div class="arch-mini__lanes">
              <div><span>request A</span><i>→</i><em>Execution A · auth-A</em><i>→</i><s>destroyed</s></div>
              <div><span>request B</span><i>→</i><em>Execution B · auth-B + auth-C</em><i>→</i><s>destroyed</s></div>
              <div><span>request C</span><i>→</i><em>Execution C · auth-D</em><i>→</i><s>destroyed</s></div>
            </div>
          </div>
          <ul>
            <li>Isolates <strong>one invocation</strong>: a temporary security domain around its Execution Context.</li>
            <li>The <strong>Execution Context</strong> holds the authority of that execution: a single authority, or an explicit composition of several. Never an implicit union.</li>
            <li>No real credentials inside. The agent holds only a <span class="soglia-term" tabindex="0" data-tip="Virtual authority bound to one Execution. The agent uses it like any API token; outside that Execution it is worthless.">VPCA</span>.</li>
            <li>Every effect on the outside world must cross a Soglia boundary.</li>
            <li>Nothing carries over: request B can never reuse request A's authority.</li>
          </ul>
        </article>
      </div>
      <blockquote class="arch-quote">Do not ask untrusted code to carry the security context correctly. <strong>Make the execution boundary carry it.</strong></blockquote>
      <p class="arch-note">Serverless popularized the per-invocation execution model as a unit of scaling. Soglia uses it as a <strong>security primitive</strong>.</p>
    </div>
  </section>
  <section id="permguard-flow" class="arch-physical">
    <div class="soglia-section-inner arch-physical__inner">
      <div class="arch-physical__text">
        <div class="soglia-kicker">Execution Context</div>
        <h2>The Execution Context carries the security. Ingress and Egress carry the traffic.</h2>
        <p>Every security decision lives in the <strong>Execution Context</strong>, with Permguard: PIC validation and exchange, policy evaluation and IFC labels. Ingress and Egress are only the physical crossing: they swap real authority for virtual on the way in, and back on the way out. They never decide.</p>
        <ul class="arch-points">
          <li><strong>Authority continuity in.</strong> The caller holds authority continuity and obtains a PCA through Permguard's PIC-X exchange.</li>
          <li><strong>Ingress: real to virtual.</strong> Ingress replaces the real PCA in the request with the Execution's VPCA. The real PCA never enters the Execution.</li>
          <li><strong>Execution Context, inbound.</strong> Validates PIC, evaluates Permguard policies and checks IFC labels before the Execution runs.</li>
          <li><strong>Execution Context, outbound.</strong> Every effect the agent proposes is evaluated against policy and its IFC labels, and authority continues through a PIC exchange, never expanding.</li>
          <li><strong>Egress: virtual to real.</strong> Egress replaces the VPCA with real authority: a PIC continuation for PIC-aware destinations, the Credential Anchor's real credential for legacy ones, and a TLS CA when needed.</li>
          <li><strong>Destroyed as a whole.</strong> The Supervisor owns the lifecycle. It tears down the entire Execution the moment an IFC label or a policy is violated, on the way in or out, and always at the end of the invocation, before the caller receives the response.</li>
        </ul>
      </div>
      <div class="arch-flow2" role="img" aria-label="Caller, Soglia Ingress, Execution Context, Execution, Execution Context, Soglia Egress, towards PIC-aware or legacy boundaries. Permguard, on the right, issues the PCA, validates PIC and evaluates policy through the Execution Context. The Supervisor, on the left, creates the Execution and destroys the whole Execution when an IFC label or policy is violated, or at the end of the invocation, before the response reaches the caller.">
          <div class="arch-row arch-row--head"><div class="arch-row__lc"><div class="arch-rail__title arch-rail__title--life">Supervisor</div><div class="arch-rail__sub">Execution lifecycle</div></div><div class="arch-row__main"></div><div class="arch-row__pg"><div class="arch-rail__title">Permguard</div><div class="arch-rail__sub">Control · Data · Trust Plane</div></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-node"><strong>Caller</strong><span>holds authority continuity</span></div></div><div class="arch-row__pg"><div class="arch-touch"><strong>PIC-X exchange</strong><span>issues the PCA</span></div></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-link"></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"><div class="arch-touch arch-touch--life"><strong>Create</strong><span>the sandbox for this call</span></div></div><div class="arch-row__main"><div class="arch-node arch-node--traffic"><strong>Soglia Ingress</strong><span>starts the Execution · traffic only · real PCA → VPCA</span></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-link"></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"><div class="arch-touch arch-touch--life"><strong>Destroy</strong><span>IFC label or policy violated</span></div></div><div class="arch-row__main"><div class="arch-ctx"><div class="arch-ctx__label">Execution Context · inbound</div><div class="arch-chips"><span>PIC validation</span><span>policy evaluation</span><span>IFC labels</span></div></div></div><div class="arch-row__pg"><div class="arch-touch"><strong>PIC validation</strong><span>PCA verified</span><strong>Policy evaluation</strong><span>what may execute</span></div></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-link"></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-soglia"><div class="arch-soglia__label">Soglia</div><div class="arch-soglia__exec">fresh Execution <b>E123</b></div><div class="arch-chips"><span>VPCA</span><span>input</span><span>labels</span></div><div class="arch-link"></div><div class="arch-node arch-node--agent"><strong>AI Agent / Workload</strong><span>untrusted code, any framework</span></div><div class="arch-soglia__foot">HTTP / gRPC only</div><div class="arch-soglia__ways"><span>↑ its answer returns through Ingress to the Caller</span><span>↓ calls it makes while running go out</span></div></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-link arch-link--label" data-label="outbound calls, while it runs"></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"><div class="arch-touch arch-touch--life"><strong>Destroy</strong><span>IFC label or policy violated</span></div></div><div class="arch-row__main"><div class="arch-ctx"><div class="arch-ctx__label">Execution Context · outbound</div><div class="arch-chips"><span>policy evaluation</span><span>PIC exchange</span><span>IFC labels</span></div></div></div><div class="arch-row__pg"><div class="arch-touch"><strong>Policy evaluation</strong><span>may this effect happen</span><strong>PIC exchange</strong><span>continuation, never expansion</span></div></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-link"></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-node arch-node--traffic"><strong>Soglia Egress</strong><span>traffic only · VPCA → real authority · TLS CA when needed</span></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-fork" aria-hidden="true"><i></i><i></i></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-split"><div class="arch-branch"><div class="arch-branch__title">PIC-aware boundary</div><div class="arch-node"><strong>PIC continuation</strong></div><div class="arch-link"></div><div class="arch-node"><strong>Connector</strong><span>or next Soglia Execution</span></div><div class="arch-link"></div><div class="arch-node"><strong>Backend effect</strong></div></div><div class="arch-branch"><div class="arch-branch__title">Legacy boundary</div><div class="arch-node"><strong>Credential Anchor</strong><span>real credential, outside the Execution</span></div><div class="arch-link"></div><div class="arch-node"><strong>External service</strong></div></div></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"></div><div class="arch-row__main"><div class="arch-link arch-link--end"></div></div><div class="arch-row__pg"></div></div>
          <div class="arch-row"><div class="arch-row__lc"><div class="arch-touch arch-touch--life"><strong>Destroy</strong><span>the whole Execution sandbox, verified</span></div></div><div class="arch-row__main"><div class="arch-node arch-node--end"><strong>Invocation ends</strong><span>the answer is back with the Caller, and nothing of the Execution remains</span></div></div><div class="arch-row__pg"></div></div>
      </div>
    </div>
  </section>
  <section id="formal" class="arch-formal">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Formal foundations</div>
        <h2>The architecture follows the model, not the other way round.</h2>
        <p class="arch-lead">Soglia, like PIC, rests on a formal theory of security-state continuity along causal execution. If a property can be proved there, Soglia implements it. If it cannot, Soglia does not pretend to enforce it.</p>
      </div>
      <div class="arch-formal__grid">
        <article>
          <div class="soglia-num">01</div>
          <h3>One security state, many dimensions</h3>
          <p>Authority, information-flow labels, relational admissibility and provenance are not separate mechanisms. They travel together, as one state carried by the execution.</p>
        </article>
        <article>
          <div class="soglia-num">02</div>
          <h3>Continuation never widens</h3>
          <p>A step is valid only if it is causally bound to the one before and no dimension becomes more permissive. Along the whole chain, every state stays within its origin.</p>
        </article>
        <article>
          <div class="soglia-num">03</div>
          <h3>Relaxation is an explicit event</h3>
          <p>When something must become more permissive, it happens as a separately authorized, auditable point in the chain, never as a side effect.</p>
        </article>
        <article>
          <div class="soglia-num">04</div>
          <h3>A partial view cannot enforce</h3>
          <p>A decision that sees only part of the state cannot enforce a property that depends on the rest. That is why the Execution Context evaluates PIC, policies and IFC labels together.</p>
        </article>
      </div>
      <div class="arch-formal__assume">
        <h3>What the model assumes, Soglia provides.</h3>
        <ul class="arch-points">
          <li><strong>Complete mediation.</strong> Every protected effect crosses Ingress or Egress, where the whole security state is read.</li>
          <li><strong>Causal binding.</strong> The Execution Context binds each accepted step to the step it actually continues.</li>
          <li><strong>No hidden shared state.</strong> A fresh Execution per invocation means caches, globals and connections cannot carry influence outside the model.</li>
        </ul>
      </div>
    </div>
  </section>
  <section class="soglia-principles arch-teaser">
    <div class="soglia-section-inner arch-teaser__inner">
      <div>
        <div class="soglia-kicker">AI Agents</div>
        <h2>Bring your own agent. Soglia brings the physics.</h2>
        <p>Any framework, unchanged. See how an agent you already have runs inside a Soglia Execution.</p>
      </div>
      <a class="soglia-btn soglia-btn--primary" :href="withBase('/agents')">AI Agents</a>
    </div>
  </section>
  <section class="arch-run">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">How an invocation runs today</div>
        <h2>By the time you read the response, its Execution is gone.</h2>
      </div>
      <ol class="arch-steps">
        <li><b>Caller</b><span>sends the request</span></li>
        <li><b>Ingress proxy</b><span>carries it to a fresh Execution</span></li>
        <li><b>Supervisor</b><span>admits it, allocates identity, address and slot</span></li>
        <li><b>Fresh sandbox</b><span>namespaces, cgroup, read-only rootfs</span></li>
        <li><b>Agent</b><span>runs, untrusted</span></li>
        <li><b>Egress proxy</b><span>the only way out, to allowed destinations</span></li>
        <li><b>Response buffered</b><span>held back until teardown</span></li>
        <li><b>Execution destroyed</b><span>verifiably gone</span></li>
        <li><b>Caller</b><span>receives the response</span></li>
      </ol>
    </div>
  </section>
  <section class="arch-components">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Components</div>
        <h2>One unprivileged coordinator, two privileged helpers.</h2>
      </div>
      <div class="arch-grid">
        <article>
          <h3>Proxy</h3>
          <p>The only way into an Execution and the only way out of it. Ingress releases the response only after the Execution is destroyed. Egress attributes every connection from trusted network facts and validates every address a destination resolves to.</p>
        </article>
        <article>
          <h3>Supervisor</h3>
          <p>The unprivileged coordinator. It admits invocations, allocates each Execution's identity, address and concurrency slot, and asks the helpers to create and destroy its resources in order.</p>
        </article>
        <article>
          <h3>sandboxd</h3>
          <p>The isolation boundary. A privileged helper that creates each Execution's cgroup, writes its OCI bundle, starts the agent with runc, proves where it runs, and destroys everything again.</p>
        </article>
        <article>
          <h3>Enforcer</h3>
          <p>The network confinement. A privileged helper that owns each Execution's network namespace, veth pair, routes and nftables rules, and the anti-spoofing that makes an Execution's address a trustworthy identity.</p>
        </article>
        <article class="arch-grid__wide">
          <h3>Linux kernel</h3>
          <p>The enforcement substrate.</p>
          <div class="arch-chips"><span>namespaces</span><span>cgroup v2</span><span>nftables</span><span>eBPF</span></div>
        </article>
      </div>
    </div>
  </section>
  <section class="arch-layers">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Two layers</div>
        <h2>Permguard decides. Soglia confines.</h2>
      </div>
      <div class="arch-layers__grid">
        <article>
          <h3>Permguard</h3>
          <p>Control Plane, Data Plane and Trust Plane: PIC, trust, policy and authority. It decides and verifies authority.</p>
        </article>
        <article>
          <h3>Soglia</h3>
          <p>The agent execution runtime: isolation, mediation, lifecycle and enforcement. It creates and confines the concrete Execution that must obey that authority.</p>
        </article>
      </div>
    </div>
  </section>
  <section class="arch-picture">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">The picture</div>
        <h2>Soglia at a glance.</h2>
      </div>
      <button type="button" class="arch-picture__frame" aria-label="Zoom the picture" @click="zoomed = true">
        <img :src="withBase('/soglia-banner.png')" alt="Soglia: the trusted runtime between Permguard and the untrusted execution sandbox" loading="lazy">
      </button>
      <div v-if="zoomed" class="arch-zoom" role="dialog" aria-modal="true" aria-label="Soglia at a glance" @click="close">
        <button type="button" class="arch-zoom__close" aria-label="Close" @click.stop="close">×</button>
        <img :src="withBase('/soglia-banner.png')" alt="Soglia: the trusted runtime between Permguard and the untrusted execution sandbox" @click.stop>
      </div>
    </div>
  </section>
  <section class="arch-status">
    <div class="soglia-section-inner">
      <div class="arch-status__box">
        <div class="soglia-kicker">Status</div>
        <h3>Target security model</h3>
        <p>This page describes the intended end-state architecture. Phase 0 proves the execution loop and the mediated network path end to end, and is not a production security release. PIC, virtual authority, Permguard integration, information-flow control, the Credential Anchor, TLS interception, gRPC, Connectors and eBPF are not part of Phase 0: their interfaces exist, and fail explicitly if they are called.</p>
        <div class="soglia-actions">
          <a class="soglia-btn soglia-btn--primary" href="https://github.com/permguard/soglia" target="_blank" rel="noopener noreferrer">View on GitHub</a>
          <a class="soglia-btn soglia-btn--ghost" :href="withBase('/')">Back to home</a>
        </div>
      </div>
    </div>
  </section>
</div>
