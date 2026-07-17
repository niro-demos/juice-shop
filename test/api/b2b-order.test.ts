/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { execSync } from 'node:child_process'
import request from 'supertest'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/b2b/v2/orders', () => {
  // Regression test for TC-CD8156F7: `orderLinesData` must never be evaluated
  // as code. Historically this field was run through a `notevil`/`vm` "safe
  // eval" sandbox, but `notevil` exposes the real `Function` constructor
  // under the `Function` identifier, so any expression escapes the sandbox
  // and runs as unrestricted server-side JavaScript (verified live: this
  // exact payload executed `id` and reflected its stdout in the response).
  void it('POST orderLinesData never executes as code, even via the notevil Function-constructor sandbox escape', async () => {
    const marker = `niro-regression-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const idOutput = execSync('id').toString().trim()

    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        orderLinesData: `Function("throw new Error('${marker} ' + process.mainModule.require('child_process').execSync('id').toString())")()`
      })

    assert.ok(res.status !== 200, `expected the payload to be rejected, got HTTP ${res.status}`)
    assert.ok(!res.text.includes(marker), 'response must not contain the unique marker from the attacker-supplied expression')
    assert.ok(!res.text.includes(idOutput), 'response must not contain server-side `id` output — the expression must never execute')
  })

  void it('POST orderLinesData containing a JavaScript expression (not JSON) is rejected', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        orderLinesData: '(function dos() { while(true); })()'
      })

    assert.equal(res.status, 400)
  })

  void it('POST orderLinesData containing a regex-based expression (not JSON) is rejected', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        orderLinesData: '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'
      })

    assert.equal(res.status, 400)
  })

  void it('POST sandbox-breakout-shaped orderLinesData (not JSON) is rejected without executing', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        orderLinesData: 'this.constructor.constructor("return process")().exit()'
      })

    assert.equal(res.status, 400)
  })

  void it('POST orderLinesData containing valid JSON (as documented in Swagger) succeeds', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        orderLinesData: '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}]'
      })

    assert.equal(res.status, 200)
    assert.equal(typeof res.body.orderNo, 'string')
  })

  void it('POST new B2B order is forbidden without authorization token', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .send({})

    assert.equal(res.status, 401)
  })

  void it('POST new B2B order accepts arbitrary valid JSON', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        foo: 'bar',
        test: 42
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    if (res.body.cid !== undefined) assert.equal(typeof res.body.cid, 'string')
    assert.equal(typeof res.body.orderNo, 'string')
    assert.equal(typeof res.body.paymentDue, 'string')
  })

  void it('POST new B2B order has passed "cid" in response', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        cid: 'test'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.cid, 'test')
  })
})
