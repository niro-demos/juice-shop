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
    assert.ok(Array.isArray(res.body.data))
    assert.equal(res.body.data.length, 1, 'an exact order id lookup must return exactly the one matching order')
    assert.equal(res.body.data[0].orderId, '5267-f9cd5882f54c75a3')
  })

  void it('GET order tracking must not leak other customers\' orders via a NoSQL injection payload in the id', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    // No real order has this literal orderId, so a correct equality lookup
    // must never surface another customer's order fields (email, price,
    // products, ...) for it - regardless of the `||`/`==` characters in the
    // payload being treated as a query condition instead of literal data.
    for (const item of res.body.data) {
      assert.equal(item.email, undefined, 'must not leak another customer\'s email')
      assert.equal(item.totalPrice, undefined, 'must not leak another customer\'s order total')
      assert.equal(item.products, undefined, 'must not leak another customer\'s order line items')
      assert.equal(item.paymentId, undefined, 'must not leak another customer\'s payment id')
    }
  })
})
