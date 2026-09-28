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
  themeConfig: {
    // `Home` is listed first, and the home page hides it (see `soglia-page-home` in custom.css).
    nav: [
      { text: 'Home', link: '/' },
      { text: 'How it works', link: '/how-it-works' },
      { text: 'AI Agents', link: '/agents' },
      { text: 'Use cases', link: '/use-cases' }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/permguard/soglia' }
    ]
  }
})
