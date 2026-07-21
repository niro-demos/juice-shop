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
import { UserModel } from '../../models/user'
import { PrivacyRequestModel } from '../../models/privacyRequests'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function csrfTokenFor (token: string) {
  const res = await request(app)
    .get('/dataerasure/')
    .set({ Cookie: 'token=' + token })
  const match = res.text.match(/name="csrfToken" value="([^"]+)"/)
  assert.ok(match)
  return match[1]
}

void describe('/dataerasure', () => {
  void it('GET erasure form for logged-in users includes their email and security question', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    const res = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + token })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('bjoern@owasp.org'))
    assert.ok(res.text.includes('Name of your favorite pet?'))
  })

  void it('GET erasure form rendering fails for users without assigned security answer', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + token })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: No answer found!'))
  })

  void it('GET erasure form rendering fails on unauthenticated access', async () => {
    const res = await request(app)
      .get('/dataerasure/')

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST erasure request does not actually delete the user', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })
    const csrfToken = await csrfTokenFor(token)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({
        email: 'bjoern@owasp.org',
        securityAnswer: 'Zaya',
        csrfToken
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    assert.equal(loginRes.status, 200)
  })

  void it('POST erasure form  fails on unauthenticated access', async () => {
    const res = await request(app)
      .post('/dataerasure/')

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST erasure request with empty layout parameter returns', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })
    const csrfToken = await csrfTokenFor(token)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ email: 'bjoern@owasp.org', securityAnswer: 'Zaya', csrfToken, layout: null })

    assert.equal(res.status, 200)
  })

  void it('POST erasure request rejects missing confirmation without creating a privacy request', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const user = await UserModel.findOne({ where: { email: 'jim@juice-sh.op' } })
    assert.ok(user)
    const countBefore = await PrivacyRequestModel.count({ where: { UserId: user.id } })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .set('Origin', 'https://attacker.example')
      .type('form')
      .send('arbitrary=x')

    assert.equal(res.status, 403)
    assert.equal(res.headers['set-cookie'], undefined)
    assert.equal(await PrivacyRequestModel.count({ where: { UserId: user.id } }), countBefore)
  })

  void it('POST erasure request ignores client-selected layout render option', async () => {
    const { token } = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
    const csrfToken = await csrfTokenFor(token)

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .type('form')
      .send({
        email: 'bender@juice-sh.op',
        securityAnswer: 'Stop\'n\'Drop',
        csrfToken,
        layout: '../package.json'
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(!res.text.includes('"name": "juice-shop"'))
    assert.ok(res.text.includes('Your erasure request will be processed shortly.'))
  })
})
