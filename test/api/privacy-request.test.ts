/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let jimUserId: number
let victimUserId: number

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token } = await login(app, {
    email: 'jim@juice-sh.op',
    password: 'ncc-1701'
  })
  authHeader = {
    Authorization: 'Bearer ' + token,
    'content-type': 'application/json'
  }
  jimUserId = 2 // seeded id for jim@juice-sh.op

  const victim = await register(app, {
    email: 'privacy-victim@test.local',
    password: 'Victim1234!'
  })
  victimUserId = victim.body.data.id
}, { timeout: 60000 })

void describe('/api/PrivacyRequests', () => {
  void it('POST new privacy request', async () => {
    const res = await request(app)
      .post('/api/PrivacyRequests')
      .set(authHeader)
      .send({
        UserId: jimUserId,
        deletionRequested: false
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(res.body.data.UserId, jimUserId)
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('POST new privacy request attributed to another user does not honor the forged UserId', async () => {
    const res = await request(app)
      .post('/api/PrivacyRequests')
      .set(authHeader)
      .send({
        UserId: victimUserId,
        deletionRequested: true
      })
    assert.equal(res.status, 201)
    assert.notEqual(res.body.data.UserId, victimUserId)
    assert.equal(res.body.data.UserId, jimUserId)
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
      .set(authHeader)
    assert.equal(res.status, 401)
  })

  void it('GET existing privacy request by id is forbidden', async () => {
    const res = await request(app)
      .get('/api/PrivacyRequests/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })

  void it('PUT update existing privacy request is forbidden', async () => {
    const res = await request(app)
      .put('/api/PrivacyRequests/1')
      .set(authHeader)
      .send({
        message: 'Should not work...'
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing privacy request is forbidden', async () => {
    const res = await request(app)
      .delete('/api/PrivacyRequests/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
