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

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, '5267-f9cd5882f54c75a3')
  })

  void it('does not return unrelated orders for an injected order id', async () => {
    const injectedOrderId = "' || true || '"
    const res = await request(app)
      .get(`/rest/track-order/${encodeURIComponent(injectedOrderId)}`)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.length <= 1)
    assert.ok(res.body.data.every((item: { orderId?: string }) => item.orderId === injectedOrderId))
  })
})
