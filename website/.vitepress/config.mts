// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vitepress'

// GitHub Pages serves the site below the repository path; the deploy workflow passes it in.
const base = `/${(process.env.VITEPRESS_BASE ?? '').replace(/^\/+|\/+$/g, '')}/`.replace(/^\/\/$/, '/')

export default defineConfig({
  base,
  title: 'Soglia',
  description: 'Trusted execution for AI agents and mission-critical workloads under authority that never expands.',
  cleanUrls: true,
  // Dark by default, like the rest of the Soglia material; the toggle still offers light.
  appearance: 'dark',
  // The Soglia symbol, cut unmodified from the official logo, as the tab icon.
  head: [['link', { rel: 'icon', type: 'image/png', href: `${base}soglia-symbol.png` }]],
  themeConfig: {
    logo: '/soglia-symbol.png',
    // `Home` is listed first, and the home page hides it (see `soglia-page-home` in custom.css).
    nav: [
      { text: 'Home', link: '/' },
      { text: 'How it works', link: '/how-it-works' },
      { text: 'Gateways', link: '/gateways' },
      { text: 'AI Agents', link: '/agents' },
      { text: 'Cloud & Infrastructure', link: '/providers' },
      { text: 'Use cases', link: '/use-cases' }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/permguard/soglia' }
    ]
  }
})
