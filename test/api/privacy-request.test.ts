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

let app: Express
let jimId: number
let jimAuthHeader: { Authorization: string, 'content-type': string }
let benderId: number

function decodeUserId (token: string): number {
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'))
  return payload.data.id
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimId = decodeUserId(jim.token)
  jimAuthHeader = { Authorization: 'Bearer ' + jim.token, 'content-type': 'application/json' }

  const bender = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
  benderId = decodeUserId(bender.token)
}, { timeout: 60000 })

void describe('/api/PrivacyRequests', () => {
  void it('POST new privacy request for the caller\'s own account', async () => {
    const res = await request(app)
      .post('/api/PrivacyRequests')
      .set(jimAuthHeader)
      .send({
        UserId: jimId,
        deletionRequested: false
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
    assert.equal(res.body.data.UserId, jimId)
  })

  void it('POST new privacy request with a different user\'s UserId in the body is bound to the caller instead', async () => {
    const res = await request(app)
      .post('/api/PrivacyRequests')
      .set(jimAuthHeader)
      .send({
        UserId: benderId,
        deletionRequested: true
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, jimId)
    assert.notEqual(res.body.data.UserId, benderId)
  })

  void it('GET all privacy requests is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/PrivacyRequests')
    assert.equal(res.status, 401)
  })
})

void describe('/api/PrivacyRequests/:id', () => {
  void it('GET all privacy requests is forbidden', async () => {
    const res = await request(app)
      .get('/api/PrivacyRequests')
      .set(jimAuthHeader)
    assert.equal(res.status, 401)
  })

  void it('GET existing privacy request by id is forbidden', async () => {
    const res = await request(app)
      .get('/api/PrivacyRequests/1')
      .set(jimAuthHeader)
    assert.equal(res.status, 401)
  })

  void it('PUT update existing privacy request is forbidden', async () => {
    const res = await request(app)
      .put('/api/PrivacyRequests/1')
      .set(jimAuthHeader)
      .send({
        message: 'Should not work...'
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing privacy request is forbidden', async () => {
    const res = await request(app)
      .delete('/api/PrivacyRequests/1')
      .set(jimAuthHeader)
    assert.equal(res.status, 401)
  })
})
