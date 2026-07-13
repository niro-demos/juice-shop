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
let benderAuthHeader: { Authorization: string, 'content-type': string }

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
  benderAuthHeader = { Authorization: 'Bearer ' + bender.token, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('/api/Complaints', () => {
  void it('POST new complaint', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(jimAuthHeader)
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

  void it('POST new complaint with a different user\'s UserId in the body is bound to the caller instead', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(jimAuthHeader)
      .send({
        message: 'forged complaint attributed to another user',
        UserId: benderId
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, jimId)
    assert.notEqual(res.body.data.UserId, benderId)
  })

  void it('GET all complaints is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Complaints')
    assert.equal(res.status, 401)
  })

  void it('GET all complaints only returns the authenticated user\'s own complaints', async () => {
    const marker = 'NIRO_PRIVATE_COMPLAINT_' + Date.now()
    const benderComplaint = await request(app)
      .post('/api/Complaints')
      .set(benderAuthHeader)
      .send({ message: 'Bender private complaint - ' + marker })
    assert.equal(benderComplaint.status, 201)
    assert.equal(benderComplaint.body.data.UserId, benderId)

    const res = await request(app)
      .get('/api/Complaints')
      .set(jimAuthHeader)
    assert.equal(res.status, 200)

    const foreignComplaints = res.body.data.filter((c: { UserId: number }) => c.UserId !== jimId)
    assert.equal(foreignComplaints.length, 0, 'expected no complaints belonging to other users in the response')

    const leaked = res.body.data.find((c: { id: number }) => c.id === benderComplaint.body.data.id)
    assert.equal(leaked, undefined, "expected bender's private complaint to not be visible to jim")
  })
})

void describe('/api/Complaints/:id', () => {
  void it('GET existing complaint by id is forbidden', async () => {
    const res = await request(app)
      .get('/api/Complaints/1')
      .set(jimAuthHeader)
    assert.equal(res.status, 401)
  })

  void it('PUT update existing complaint is forbidden', async () => {
    const res = await request(app)
      .put('/api/Complaints/1')
      .set(jimAuthHeader)
      .send({
        message: 'Should not work...'
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing complaint is forbidden', async () => {
    const res = await request(app)
      .delete('/api/Complaints/1')
      .set(jimAuthHeader)
    assert.equal(res.status, 401)
  })
})
