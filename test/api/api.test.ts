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

void describe('/api', () => {
  void it('GET error when query /api without actual resource', async () => {
    const res = await request(app)
      .get('/api')
    assert.equal(res.status, 500)
  })
})

void describe('/rest', () => {
  void it('GET error message without internal details when calling unrecognized path with /rest in it', async () => {
    const res = await request(app)
      .get('/rest/unrecognized')
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected path: /rest/unrecognized'))
    assert.equal(res.text.includes('OWASP Juice Shop (Express'), false)
    assert.equal(res.text.includes('<pre>'), false)
  })
})
