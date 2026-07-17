/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }

let jimAuthHeader: { Authorization: string, 'content-type': string }
let jimId: number
let benderAuthHeader: { Authorization: string, 'content-type': string }

before(async () => {
  const result = await createTestApp()
  app = result.app

  const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimAuthHeader = { Authorization: 'Bearer ' + jim.token, 'content-type': 'application/json' }
  jimId = 2 // jim is seeded as user id 2 (see test/api/memory.test.ts: 'POST new memory ...' asserts UserId === 2 for jim)

  const bender = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
  benderAuthHeader = { Authorization: 'Bearer ' + bender.token, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('/api/Recycles', () => {
  void it('POST new recycle', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        quantity: 200,
        AddressId: '1',
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('Will prevent GET all recycles from this endpoint', async () => {
    const res = await request(app)
      .get('/api/Recycles')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.err, 'Sorry, this endpoint is not supported.')
  })

  void it('PUT update existing recycle is forbidden', async () => {
    const res = await request(app)
      .put('/api/Recycles/1')
      .set(authHeader)
      .send({
        quantity: 100000
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing recycle is forbidden', async () => {
    const res = await request(app)
      .delete('/api/Recycles/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})

void describe('/api/Recycles/:id', () => {
  let jimRecycleId: number

  before(async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(jimAuthHeader)
      .send({
        quantity: 100,
        AddressId: '1',
        isPickup: false,
        date: '2017-06-01',
        UserId: jimId
      })
    assert.equal(res.status, 201)
    jimRecycleId = res.body.data.id
  })

  void it('an unauthenticated caller cannot read any recycle record, including by bulk id-array injection', async () => {
    const single = await request(app)
      .get(`/api/Recycles/${jimRecycleId}`)
    assert.equal(single.status, 401)

    // Regression for JSON.parse(req.params.id) being fed straight into a Sequelize `where`,
    // letting an unauthenticated caller enumerate every record via an IN-style array id.
    const bulk = await request(app)
      .get(`/api/Recycles/${encodeURIComponent(`[${jimRecycleId}]`)}`)
    assert.equal(bulk.status, 401)
  })

  void it('the owner can GET their own existing recycle record', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${jimRecycleId}`)
      .set(jimAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const items = res.body.data
    assert.ok(Array.isArray(items))
    assert.ok(items.length > 0)
    for (const item of items) {
      assert.equal(typeof item.id, 'number')
      assert.equal(typeof item.UserId, 'number')
      assert.equal(typeof item.AddressId, 'number')
      assert.equal(typeof item.quantity, 'number')
      assert.equal(typeof item.isPickup, 'boolean')
      assert.ok(item.date !== undefined)
      assert.equal(typeof item.createdAt, 'string')
      assert.equal(typeof item.updatedAt, 'string')
    }
  })

  void it('a different authenticated user cannot read another user\'s recycle record by id', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${jimRecycleId}`)
      .set(benderAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.deepEqual(res.body.data, [])
  })

  void it('a JSON array id is rejected instead of being used to enumerate multiple records at once', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${encodeURIComponent(`[${jimRecycleId},1,2,3]`)}`)
      .set(jimAuthHeader)
    assert.equal(res.status, 400)
  })
})
