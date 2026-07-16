/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/ftp', () => {
  const blockedPaths = [
    { path: '/ftp', markers: ['<title>listing directory /ftp</title>'] },
    { path: '/ftp/acquisitions.md', markers: ['# Planned Acquisitions', 'This document is confidential'] },
    { path: '/ftp/incident-support.kdbx', markers: [] },
    { path: '/ftp/eastere.gg%2500.pdf', markers: ['Congratulations, you found the easter egg!'] },
    { path: '/ftp/suspicious_errors.yml%2500.md', markers: ['Suspicious error messages specific to the application'] },
    { path: '/ftp/coupons_2013.md.bak%2500.md', markers: ['n<MibgC7sn'] },
    { path: '/ftp/package.json.bak%2500.md', markers: ['"name": "juice-shop"', '"epilogue-js": "~0.7"'] },
    { path: '/ftp/legal.md', markers: ['# Legal Information'] },
    { path: '/ftp/quarantine/juicy_malware_windows_64.exe.url', markers: ['URL=https://github.com/juice-shop/juicy-malware'] }
  ]

  for (const { path, markers } of blockedPaths) {
    void it(`GET ${path} is blocked`, async () => {
      const res = await request(app)
        .get(path)
        .buffer(true)
      const text = res.text ?? (Buffer.isBuffer(res.body) ? res.body.toString('utf8') : '')

      assert.equal(res.status, 404)
      for (const marker of markers) {
        assert.ok(!text.includes(marker))
      }
    })
  }
})
