---
layout: page
pageClass: soglia-page-home
title: Soglia Runtime
description: Trusted execution for AI agents and mission-critical workloads under authority that never expands.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Icons adapted from Lucide (https://lucide.dev), ISC License. -->

<script setup>
import { withBase } from 'vitepress'
</script>

<div class="soglia-home">
  <section class="soglia-hero">
    <svg class="soglia-rails" viewBox="0 0 720 610" aria-hidden="true" focusable="false">
      <g class="soglia-rail" transform="translate(470 64)">
        <path class="soglia-rail__rails" d="M-800 -4H800M-800 4H800"/>
        <path class="soglia-rail__ties" d="M-800 0H800"/>
        <circle class="soglia-rail__car" r="2.5"/>
        <rect class="soglia-rail__arm" x="-0.75" y="-18" width="1.5" height="32" rx="0.75"/>
        <circle class="soglia-rail__post" cy="14" r="2"/>
      </g>
      <g class="soglia-rail" transform="translate(390 500)">
        <path class="soglia-rail__rails" d="M-800 -4H800M-800 4H800"/>
        <path class="soglia-rail__ties" d="M-800 0H800"/>
        <circle class="soglia-rail__car" r="2.5"/>
        <rect class="soglia-rail__arm" x="-0.75" y="-18" width="1.5" height="32" rx="0.75"/>
        <circle class="soglia-rail__post" cy="14" r="2"/>
      </g>
      <g class="soglia-rail" transform="translate(560 566)">
        <path class="soglia-rail__rails" d="M-800 -4H800M-800 4H800"/>
        <path class="soglia-rail__ties" d="M-800 0H800"/>
        <circle class="soglia-rail__car" r="2.5"/>
        <rect class="soglia-rail__arm" x="-0.75" y="-18" width="1.5" height="32" rx="0.75"/>
        <circle class="soglia-rail__post" cy="14" r="2"/>
      </g>
    </svg>
    <div class="soglia-hero__copy">
      <div class="soglia-kicker">Soglia Runtime</div>
      <h1>Trusted execution for AI agents and mission-critical workloads.</h1>
      <p>Every call runs in its own isolated Execution, where <strong>authority becomes physical</strong>: enforced at runtime by the kernel, never expanding, and leaving nothing behind.</p>
      <div class="soglia-actions">
        <a class="soglia-btn soglia-btn--primary" :href="withBase('/how-it-works')">How it works</a>
        <a class="soglia-btn soglia-btn--ghost" href="https://github.com/permguard/soglia" target="_blank" rel="noopener noreferrer">View on GitHub</a>
      </div>
    </div>
    <div class="soglia-hero__brand" aria-label="Soglia">
      <img class="soglia-logo soglia-logo--light" src="/soglia-logo-light.png" alt="Soglia">
      <img class="soglia-logo soglia-logo--dark" src="/soglia-logo-dark.png" alt="Soglia">
    </div>
  </section>
  <section class="soglia-threshold">
    <div class="soglia-section-inner soglia-threshold__inner">
      <h2>The threshold</h2>
      <p>Soglia is Italian for <strong>threshold</strong>: the boundary something must cross before it can have an effect on the outside world.</p>
      <p class="soglia-threshold__accent">For an autonomous agent, Soglia is that boundary.</p>
    </div>
  </section>
  <section id="principles" class="soglia-principles">
    <div class="soglia-section-inner">
      <div class="soglia-principles__grid">
        <article>
          <div class="soglia-num">01</div>
          <h3>Fresh Execution</h3>
          <p>One request = one authority context = one fresh isolated Execution.</p>
        </article>
        <article>
          <div class="soglia-num">02</div>
          <h3>Mediated Effects</h3>
          <p>If the agent wants to affect the outside world, the effect must cross a Soglia boundary.</p>
        </article>
        <article>
          <div class="soglia-num">03</div>
          <h3>Authority Continuity</h3>
          <p>PIC proves why authority may continue. Soglia makes that authority enforceable.</p>
        </article>
      </div>
    </div>
  </section>
  <section class="soglia-flows">
    <div class="soglia-section-inner soglia-flows__inner">
      <p><strong>PIC</strong> controls authority flow.</p>
      <p><strong>IFC</strong> controls information flow.</p>
      <p><strong class="soglia-flows__soglia">Soglia</strong> controls execution and effect flow.</p>
    </div>
  </section>
  <section id="philosophy" class="soglia-principles soglia-philosophy">
    <div class="soglia-section-inner soglia-philosophy__inner">
      <div>
        <div class="soglia-kicker">Philosophy</div>
        <h2>If it cannot be proven, it does not ship.</h2>
        <p>Soglia is built the way PIC is: formal model first. A mechanism enters Soglia only when the property it enforces can be stated and proved. Whatever cannot be proved stays out, however convenient it would be.</p>
      </div>
      <ol class="soglia-philosophy__steps">
        <li><b>Stated</b><span>every guarantee is a formal property, not a promise</span></li>
        <li><b>Proved</b><span>it holds along the whole causal chain of an execution</span></li>
        <li><b>Enforced</b><span>Soglia supplies exactly what the proof assumes</span></li>
      </ol>
    </div>
  </section>
  <section id="benefits" class="soglia-benefits">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Benefits</div>
        <h2>What Soglia is built for</h2>
      </div>
      <div class="soglia-benefits__grid">
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
          <h3>No standing privileges</h3>
          <p>An agent holds authority only for the call it serves, and never more than it was given.</p>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></svg>
          <h3>No cross-contamination</h3>
          <p>One call can never see, reuse or leak the state or credentials of another.</p>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="m8.59 13.51 6.83 3.98"/><path d="m15.41 6.51-6.82 3.98"/></svg>
          <h3>No secrets to steal</h3>
          <p>Real credentials never reach agent code, so a compromised agent has nothing worth taking.</p>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <h3>Fail-closed</h3>
          <p>When something cannot be verified, Soglia blocks instead of exposing.</p>
        </article>
      </div>
    </div>
  </section>
  <section id="permguard" class="soglia-permguard">
    <div class="soglia-section-inner soglia-permguard__inner">
      <div class="soglia-permguard__intro">
        <img class="soglia-permguard__logo soglia-permguard__logo--white-txt" src="/permguard/logo-white-txt.svg" alt="Permguard">
        <img class="soglia-permguard__logo soglia-permguard__logo--dark-txt" src="/permguard/logo-dark-txt.png" alt="Permguard">
        <h2>Integrate Permguard</h2>
        <p>Permguard defines, proves and governs authority. Soglia makes its boundary physical.</p>
        <div class="soglia-actions">
          <a class="soglia-btn soglia-btn--primary" href="https://permguard.com" target="_blank" rel="noopener noreferrer">Discover Permguard</a>
        </div>
      </div>
      <div class="soglia-permguard__items">
        <article>
          <h3>Policies</h3>
          <p>Authorization policies stored in content-addressed ledgers and distributed as signed versions.</p>
        </article>
        <article>
          <h3>PIC</h3>
          <p>Carries authority from one step to the next, and proves it never grew on the way.</p>
        </article>
        <article>
          <h3>Governance</h3>
          <p>Decisions evaluated in the Permguard data plane or embedded in a process, with a verifiable history of every policy change.</p>
        </article>
      </div>
    </div>
  </section>
  <section id="use-cases" class="soglia-usecases">
    <div class="soglia-section-inner">
      <div class="soglia-section-head">
        <div class="soglia-kicker">Use cases</div>
        <h2>Deploy anywhere</h2>
      </div>
      <div class="soglia-usecases__grid">
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>
          <h3>Cloud &amp; Enterprise AI</h3>
          <p>Secure execution of AI agents and enterprise workloads in cloud and hybrid environments.</p>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/></svg>
          <h3>Local AI &amp; GPU systems</h3>
          <p>Run on-premise LLMs with control and complete isolation.</p>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M2 20a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8l-7 5V8l-7 5V4a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2Z"/><path d="M17 18h1M12 18h1M7 18h1"/></svg>
          <h3>IoT &amp; Edge devices</h3>
          <p>Bring AI to edge devices and industrial environments, safely and verifiably.</p>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 .709-1.528l7-5.999a2 2 0 0 1 2.582 0l7 5.999A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
          <h3>Smart Home &amp; Building Automation</h3>
          <p>AI agents for homes and smart buildings, with controlled access.</p>
        </article>
        <article>
          <svg class="soglia-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2M20 14h2M15 13v2M9 13v2"/></svg>
          <h3>Robotics &amp; Operational Systems</h3>
          <p>Controlled, verifiable execution for mission-critical robotic and operational systems.</p>
        </article>
      </div>
      <div class="soglia-actions soglia-usecases__more">
        <a class="soglia-btn soglia-btn--ghost" :href="withBase('/use-cases')">Explore use cases</a>
      </div>
    </div>
  </section>
</div>
