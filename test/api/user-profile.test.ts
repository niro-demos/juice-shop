/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as datacache from '../../data/datacache'

let app: Express
let authHeader: { Cookie: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  authHeader = { Cookie: `token=${token}` }
}, { timeout: 60000 })

void describe('/profile', () => {
  void it('GET user profile is forbidden for unauthenticated user', async () => {
    const res = await request(app)
      .get('/profile')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`<h1>${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET user profile of authenticated user', async () => {
    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('id="email" type="email" name="email" value="jim@juice-sh.op"'))
  })

  void it('POST update username of authenticated user', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', 'Localhorst')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST update profile is forbidden for unauthenticated user', async () => {
    const res = await request(app)
      .post('/profile')
      .field('username', 'Anonhorst')

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  // Regression test for TC-63FCA124: the username field must never be passed
  // to eval() (or any other code-execution sink) — it is a display-name
  // string only, no matter what it looks like syntactically.
  void it('GET user profile never executes JavaScript from the username field, even a command-execution payload (regression: TC-63FCA124)', async () => {
    const marker = `niro-rce-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const payload = `#{require('child_process').execSync('echo ${marker}').toString().trim()}`

    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: payload })
      .redirects(0)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    // If the payload had been executed, the rendered text would be *only*
    // the echoed marker, with no trace of the `require(...)`/`execSync(...)`
    // source. Asserting the full literal payload is present proves it was
    // never executed — a weaker "output not found" check alone would not,
    // since the marker also appears verbatim inside the un-executed source.
    assert.ok(res.text.includes(payload), 'username must be rendered as the literal, unexecuted text the user submitted')
    const executedOutputOnly = new RegExp(`>\\s*${marker}\\s*<`)
    assert.ok(!executedOutputOnly.test(res.text), 'profile page must not contain the bare output of a server-executed command')
  })

  void it('GET user profile renders an eval-syntax username (e.g. "#{7*7}") as literal text, not an evaluated expression', async () => {
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: '#{7*7}' })
      .redirects(0)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(!res.text.includes('>49<'), 'the expression must not be evaluated')
    assert.ok(res.text.includes('#{7*7}'), 'the literal text should be rendered verbatim')
  })

  void it('GET user profile falls back gracefully when SSTI payload throws', async () => {
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: '#{not_a_defined_symbol}' })
      .redirects(0)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('not_a_defined_symbol'))
  })

  void it('should be solved when origin header matches configured CSRF URL', async () => {
    const csrfUrl = config.get<string>('challenges.overwriteUrlForCsrfChallenge')
    datacache.challenges.csrfChallenge.solved = false
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', csrfUrl)
      .send({ username: 'CSRF_Victim' })
      .expect(302)
    assert.equal(datacache.challenges.csrfChallenge.solved, true)
  })

  void it('should have the configured CSRF URL in the challenge description', async () => {
    const csrfUrl = config.get<string>('challenges.overwriteUrlForCsrfChallenge')
    assert.ok(datacache.challenges.csrfChallenge.description.includes(csrfUrl))
  })

  void it('should NOT be solved when origin header does NOT match configured CSRF URL', async () => {
    datacache.challenges.csrfChallenge.solved = false
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'http://attacker.com')
      .send({ username: 'No_CSRF' })
      .expect(302)
    assert.equal(datacache.challenges.csrfChallenge.solved, false)
  })
})
