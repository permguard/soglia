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
    nav: [
      { text: 'Architecture', link: '/architecture' }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/permguard/soglia' }
    ]
  }
})
