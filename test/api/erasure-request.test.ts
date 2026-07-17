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

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

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
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .field('email', 'bjoern.kimminich@gmail.com')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    assert.equal(loginRes.status, 200)
  })

  void it('POST erasure form  fails on unauthenticated access', async () => {
    const res = await request(app)
      .post('/dataerasure/')

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST erasure request with empty layout parameter returns', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ layout: null })

    assert.equal(res.status, 200)
  })

  void it('POST erasure request ignores a `layout` parameter that traverses to a non-existing filesystem path', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ layout: '../this/file/does/not/exist' })

    // The layout value must never be resolved as a filesystem path, so a
    // nonexistent traversal target must not surface an ENOENT/stack trace —
    // the fixed confirmation template renders normally instead.
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('no such file or directory'))
    assert.ok(res.text.includes('Sorry to see you leave'))
  })

  void it('POST erasure request ignores a `layout` parameter naming a real file and never discloses its contents', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ layout: '../package.json' })

    // Invariant: the data-erasure endpoint must only ever render its own
    // fixed confirmation template, never a client-chosen file's contents.
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('"name": "juice-shop"'))
    assert.ok(res.text.includes('Sorry to see you leave'))
  })

  void it('POST erasure request ignores a `layout` parameter naming an unrelated existing view', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    // Positive control: a legitimate request (no layout override) renders
    // the fixed confirmation content.
    const legitRes = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ email: 'bjoern.kimminich@gmail.com' })
    assert.equal(legitRes.status, 200)
    assert.ok(legitRes.text.includes('Sorry to see you leave'))

    // Exploit attempt: `layout` names a real, unrelated view file
    // (dataErasureForm.hbs). Per the invariant this must be ignored — the
    // response must still be the fixed confirmation, never the other view.
    const res = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .send({ layout: 'dataErasureForm' })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('Sorry to see you leave'))
    assert.ok(!res.text.includes('Data Erasure Request (Art. 17 GDPR)'))
  })
})
