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

void describe('/support/logs/:file', () => {
  void it('GET blocks access log file for the current day', async () => {
    const res = await request(app)
      .get('/support/logs/access.log.2026-01-01')

    assert.equal(res.status, 404)
  })

  void it('GET log file whose name contains a forward slash is blocked', async () => {
    const res = await request(app)
      .get('/support/logs/%2fetc%2fpasswd')

    assert.equal(res.status, 404)
  })
})
