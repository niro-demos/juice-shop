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

function hasOrderHistoryFields (item: any) {
  return item !== undefined &&
    typeof item === 'object' &&
    typeof item.orderId === 'string' &&
    (typeof item.email === 'string' ||
      typeof item.totalPrice === 'number' ||
      Array.isArray(item.products) ||
      typeof item.delivered === 'boolean' ||
      typeof item._id === 'string')
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    assert.equal(res.body.data[0].orderId, '5267-f9cd5882f54c75a3')
  })

  void it('rejects tracking ids that inject query predicates', async () => {
    const res = await request(app)
      .get('/rest/track-order/x%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 400)
    assert.equal(Array.isArray(res.body.data) && res.body.data.some(hasOrderHistoryFields), false)
  })

  void it('rejects tracking ids containing HTML before they reach the result page', async () => {
    const res = await request(app)
      .get('/rest/track-order/%3Cimg%20src%3Dx%20onerror%3D%22document.title%3D1%22%3E')
    assert.equal(res.status, 400)
    assert.equal(res.body.data, undefined)
  })
})
