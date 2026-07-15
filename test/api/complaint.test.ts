/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import jwt from 'jsonwebtoken'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let benderAuthHeader: { Authorization: string, 'content-type': string }
let jimId: number
let benderId: number

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    authHeader = { Authorization: 'Bearer ' + jim.token, 'content-type': 'application/json' }
    jimId = (jwt.decode(jim.token) as { data: { id: number } }).data.id

    const bender = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
    benderAuthHeader = { Authorization: 'Bearer ' + bender.token, 'content-type': 'application/json' }
    benderId = (jwt.decode(bender.token) as { data: { id: number } }).data.id
  },
  { timeout: 60000 }
)

void describe('/api/Complaints', () => {
  void it('POST new complaint', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({
        message: 'You have no clue what https://github.com/eslint/eslint-scope/issues/39 means, do you???'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
    assert.equal(res.body.data.UserId, jimId)
  })

  void it('GET all complaints is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Complaints')
    assert.equal(res.status, 401)
  })

  void it('GET all complaints', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('GET all complaints only returns the caller\'s own complaints', async () => {
    const benderSecret = `bender-private-complaint-${Date.now()}`
    const benderPost = await request(app)
      .post('/api/Complaints')
      .set(benderAuthHeader)
      .send({ message: benderSecret })
    assert.equal(benderPost.status, 201)

    const jimMessage = `jim-own-complaint-${Date.now()}`
    const jimPost = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({ message: jimMessage })
    assert.equal(jimPost.status, 201)

    const listRes = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(listRes.status, 200)

    const messages: string[] = listRes.body.data.map((c: { message: string }) => c.message)
    // Positive control: the caller's own, freshly-posted complaint must be visible.
    assert.ok(messages.includes(jimMessage), 'expected the caller\'s own complaint to be listed')
    // The finding: another customer's complaint must never be visible to the caller.
    assert.ok(!messages.includes(benderSecret), 'must not leak another customer\'s complaint')
    assert.ok(
      (listRes.body.data as Array<{ UserId: number }>).every(c => c.UserId === jimId),
      'every complaint returned to the caller must belong to the caller'
    )
  })

  void it('POST new complaint ignores a client-supplied UserId and attributes it to the authenticated user', async () => {
    const forgedMessage = `forged-complaint-${Date.now()}`
    const res = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({ message: forgedMessage, UserId: benderId })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, jimId, 'complaint must be attributed to the authenticated caller, not the forged UserId')
    assert.notEqual(res.body.data.UserId, benderId)
  })
})

void describe('/api/Complaints/:id', () => {
  void it('GET existing complaint by id is forbidden', async () => {
    const res = await request(app)
      .get('/api/Complaints/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })

  void it('PUT update existing complaint is forbidden', async () => {
    const res = await request(app)
      .put('/api/Complaints/1')
      .set(authHeader)
      .send({
        message: 'Should not work...'
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing complaint is forbidden', async () => {
    const res = await request(app)
      .delete('/api/Complaints/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
