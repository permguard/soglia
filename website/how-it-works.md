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
onMounted(() => {
  window.addEventListener('keydown', onKey)
  // The guardrail diagram animates with SMIL, which CSS cannot stop: pause it for reduced motion.
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    document.querySelectorAll('.gd-svg').forEach((svg) => svg.pauseAnimations())
  }
})
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
  <section class="soglia-principles uc-pattern">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">One pattern</div>
        <h2>Every call takes the same path.</h2>
      </div>
      <ol class="uc-path" aria-label="Call, Ingress, Execution Context, Sandboxed Invocation inside a kernel-enforced boundary, Execution Context, Egress">
        <li class="uc-path__step"><span class="uc-path__tag">Call</span><small>a request, an event, a trigger</small></li>
        <li class="uc-path__step uc-path__step--traffic"><span class="uc-path__tag">Ingress</span><small>traffic in</small></li>
        <li class="uc-path__step uc-path__step--ctx"><span class="uc-path__tag">Execution Context</span><small>validates on the way in</small></li>
        <li class="uc-path__step uc-path__step--core">
          <span class="uc-path__kernel"><span class="uc-path__tag">Sandboxed Invocation</span></span>
          <small>AI agent or mission-critical workload</small>
        </li>
        <li class="uc-path__step uc-path__step--ctx"><span class="uc-path__tag">Execution Context</span><small>validates on the way out</small></li>
        <li class="uc-path__step uc-path__step--traffic"><span class="uc-path__tag">Egress</span><small>traffic out</small></li>
      </ol>
      <div class="uc-define">
        <h3>What is a sandboxed invocation?</h3>
        <p>One run of a mission-critical process: an AI agent reasoning over a ticket, a control loop deciding a setpoint, a job moving money. It is started for one call, confined for its whole life, and destroyed when it ends. What it may touch is decided by its Execution Context, not by the process itself.</p>
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
  <section class="arch-guard">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Policies and guardrails</div>
        <h2>An execution can skip a guardrail. Its successor will not accept it.</h2>
        <p class="arch-guard__lead">Not every policy does the same job. Some shape where an execution may run and what it may touch. Others decide whether the authority it carries may continue. Soglia enforces the first inside the Execution Context. PIC carries the second, with trust anchors as guardrails.</p>
      </div>
      <div class="arch-policies">
        <article>
          <div class="arch-policies__kind">Execution policies</div>
          <h3>Infrastructure and application</h3>
          <p>Where the execution may connect, which resources it may use, which calls may leave and under which labels. Soglia enforces them in the Execution Context, for this execution, on this node.</p>
        </article>
        <article class="arch-policies__pic">
          <div class="arch-policies__kind">Security policies</div>
          <h3>Authority, with PIC</h3>
          <p>Whether the authority an execution carries may continue to the next step. Guardrails are trust anchors: their answer becomes part of the continuation itself, intersected with the authority that was carried, so the next step can only receive less.</p>
        </article>
      </div>
      <figure class="gd-figure">
        <figcaption class="soglia-kicker">The trust anchor is part of the protocol</figcaption>
        <svg class="gd-svg gd-svg--wide" viewBox="0 0 800 270" role="img" aria-label="An execution continues through the trust anchor, whose answer is intersected with its authority, and the next execution accepts it. The same execution going around the trust anchor reaches the next execution, which rejects it.">
          <path class="gd-bypass" d="M130 118 C130 26 670 26 670 118"><animate attributeName="stroke-opacity" values=".35;.35;1;1;.35;.35" keyTimes="0;.52;.53;.78;.82;1" dur="10s" repeatCount="indefinite"/></path>
          <text class="gd-note" x="400" y="34">around the trust anchor</text>
          <line class="gd-link" x1="220" y1="150" x2="580" y2="150"/>
          <circle class="gd-token" r="6"><animateMotion path="M220 150 L580 150" keyPoints="0;.25;.75;1;1" keyTimes="0;.1;.2;.3;1" calcMode="linear" dur="10s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;1;1;0;0" keyTimes="0;.01;.3;.31;1" dur="10s" repeatCount="indefinite"/></circle>
          <circle class="gd-token gd-token--bad" r="6" opacity="0"><animateMotion path="M130 118 C130 26 670 26 670 118" keyPoints="0;0;1;1" keyTimes="0;.52;.76;1" calcMode="linear" dur="10s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes="0;.52;.53;.76;.77;1" dur="10s" repeatCount="indefinite"/></circle>
          <g class="gd-node"><rect x="40" y="118" width="180" height="64" rx="12"/><text class="gd-title" x="130" y="146">Execution</text><text class="gd-sub" x="130" y="166">carries its authority</text></g>
          <rect class="gd-ring" x="303" y="111" width="194" height="78" rx="16" opacity="0"><animate attributeName="opacity" values="0;0;1;0;0" keyTimes="0;.1;.15;.24;1" dur="10s" repeatCount="indefinite"/></rect>
          <g class="gd-node gd-node--anchor"><rect x="310" y="118" width="180" height="64" rx="12"/><text class="gd-title" x="400" y="146">Trust anchor</text><text class="gd-sub" x="400" y="166">the guardrail</text></g>
          <g class="gd-meet" opacity="0"><circle cx="490" cy="118" r="14"/><text x="490" y="124">∩</text><animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes="0;.12;.15;.3;.34;1" dur="10s" repeatCount="indefinite"/></g>
          <g class="gd-node"><rect x="580" y="118" width="180" height="64" rx="12"/><text class="gd-title" x="670" y="146">Next execution</text><text class="gd-sub" x="670" y="166">verifies the continuation</text></g>
          <g class="gd-ok" opacity="0"><circle cx="630" cy="222" r="11"/><path d="M625 222 l4 4 l7 -8"/><text x="648" y="227">accepted</text><animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes="0;.3;.32;.44;.47;1" dur="10s" repeatCount="indefinite"/></g>
          <g class="gd-ko" opacity="0"><circle cx="630" cy="222" r="11"/><path d="M625 217 l10 10 M635 217 l-10 10"/><text x="648" y="227">rejected</text><animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes="0;.76;.78;.92;.95;1" dur="10s" repeatCount="indefinite"/></g>
        </svg>
        <svg class="gd-svg gd-svg--tall" viewBox="0 0 360 600" role="img" aria-label="An execution continues through the trust anchor, whose answer is intersected with its authority, and the next execution accepts it. The same execution going around the trust anchor reaches the next execution, which rejects it.">
          <path class="gd-bypass" d="M280 62 C352 62 352 518 280 518"><animate attributeName="stroke-opacity" values=".35;.35;1;1;.35;.35" keyTimes="0;.52;.53;.78;.82;1" dur="10s" repeatCount="indefinite"/></path>
          <text class="gd-note" x="350" y="290" transform="rotate(90 350 290)">around the trust anchor</text>
          <line class="gd-link" x1="180" y1="94" x2="180" y2="486"/>
          <circle class="gd-token" r="6"><animateMotion path="M180 94 L180 486" keyPoints="0;.418;.582;1;1" keyTimes="0;.1;.2;.3;1" calcMode="linear" dur="10s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;1;1;0;0" keyTimes="0;.01;.3;.31;1" dur="10s" repeatCount="indefinite"/></circle>
          <circle class="gd-token gd-token--bad" r="6" opacity="0"><animateMotion path="M280 62 C352 62 352 518 280 518" keyPoints="0;0;1;1" keyTimes="0;.52;.76;1" calcMode="linear" dur="10s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes="0;.52;.53;.76;.77;1" dur="10s" repeatCount="indefinite"/></circle>
          <g class="gd-node"><rect x="80" y="30" width="200" height="64" rx="12"/><text class="gd-title" x="180" y="58">Execution</text><text class="gd-sub" x="180" y="78">carries its authority</text></g>
          <rect class="gd-ring" x="73" y="251" width="214" height="78" rx="16" opacity="0"><animate attributeName="opacity" values="0;0;1;0;0" keyTimes="0;.1;.15;.24;1" dur="10s" repeatCount="indefinite"/></rect>
          <g class="gd-node gd-node--anchor"><rect x="80" y="258" width="200" height="64" rx="12"/><text class="gd-title" x="180" y="286">Trust anchor</text><text class="gd-sub" x="180" y="306">the guardrail</text></g>
          <g class="gd-meet" opacity="0"><circle cx="80" cy="258" r="14"/><text x="80" y="264">∩</text><animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes="0;.12;.15;.3;.34;1" dur="10s" repeatCount="indefinite"/></g>
          <g class="gd-node"><rect x="80" y="486" width="200" height="64" rx="12"/><text class="gd-title" x="180" y="514">Next execution</text><text class="gd-sub" x="180" y="534">verifies the continuation</text></g>
          <g class="gd-ok" opacity="0"><circle cx="146" cy="578" r="11"/><path d="M141 578 l4 4 l7 -8"/><text x="164" y="583">accepted</text><animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes="0;.3;.32;.44;.47;1" dur="10s" repeatCount="indefinite"/></g>
          <g class="gd-ko" opacity="0"><circle cx="146" cy="578" r="11"/><path d="M141 573 l10 10 M151 573 l-10 10"/><text x="164" y="583">rejected</text><animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes="0;.76;.78;.92;.95;1" dur="10s" repeatCount="indefinite"/></g>
        </svg>
        <ul class="gd-legend">
          <li class="gd-legend__ok"><strong>Through the trust anchor.</strong> Its answer is intersected with the authority carried, and the result becomes the continuation. The next execution accepts it.</li>
          <li class="gd-legend__ko"><strong>Around it.</strong> The path reaches the next execution, but the continuation lacks the trust anchor's part. The next execution rejects it.</li>
        </ul>
      </figure>
      <blockquote class="arch-quote">The execution can leave the guardrail behind. <strong>Its authority cannot.</strong><span class="arch-quote__more">PIC does not make a bypass physically impossible: it makes the bypassed path invalid, so no conforming successor accepts it. Soglia adds the physical side, with the kernel keeping every execution on the mediated path.</span></blockquote>
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
      <blockquote class="arch-quote">Do not ask untrusted code to carry the security context correctly. <strong>Make the execution boundary carry it.</strong><span class="arch-quote__more">Serverless popularized the per-invocation execution model as a unit of scaling. Soglia uses it as a <strong>security primitive</strong>.</span></blockquote>
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
