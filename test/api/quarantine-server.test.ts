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

void describe('/ftp/quarantine/:file', () => {
  void it('GET denies a known quarantined file', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_windows_64.exe.url')

    assert.ok([401, 403, 404].includes(res.status))
    assert.ok(!res.text.includes('juicy_malware_windows_64.exe'))
  })

  void it('GET denies a filename containing a forward slash', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/' + encodeURIComponent('../package.json'))

    assert.ok([401, 403, 404].includes(res.status))
    assert.ok(!res.text.includes('"name": "juice-shop"'))
  })
})
