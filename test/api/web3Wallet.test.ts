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
let authHeader: { Authorization: string, 'content-type': string }

void describe('/rest/web3/walletExploitAddress', () => {
  before(async () => {
    const result = await createTestApp()
    app = result.app
    const { token } = await login(app, { email: 'demo', password: 'demo' })
    authHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
  }, { timeout: 60000 })

  void it('POST missing wallet address in unauthenticated request is forbidden', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({})

    assert.equal(res.status, 401)
  })

  void it('POST invalid wallet address in unauthenticated request is forbidden', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({ walletAddress: 'lalalalala' })

    assert.equal(res.status, 401)
  })

  void it('POST invalid wallet address in authenticated request is rejected', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .set(authHeader)
      .send({ walletAddress: 'lalalalala' })

    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.error, 'Invalid wallet address')
  })

  const skipReason = process.env.ALCHEMY_API_KEY ? undefined : 'ALCHEMY_API_KEY not set'

  void it('POST self-referential address in request body leads to success notification', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .set(authHeader)
      .send({ walletAddress: '0x413744D59d31AFDC2889aeE602636177805Bd7b0' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Event Listener Created')
  }, { skip: skipReason })
})
