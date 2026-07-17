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

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/change-password', () => {
  void it('POST password change for newly created user with recognized token as Authorization header', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kuni@be.rt',
        password: 'kunigunde'
      })
      .expect(201)

    const { token } = await login(app, { email: 'kuni@be.rt', password: 'kunigunde' })

    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ current: 'kunigunde', new: 'foo', repeat: 'foo' })

    assert.equal(res.status, 200)
  })

  void it('POST password change with passing wrong current password', async () => {
    const { token } = await login(app, {
      email: 'bjoern@' + config.get<string>('application.domain'),
      password: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase'
    })

    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ current: 'definetely_wrong', new: 'blubb', repeat: 'blubb' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Current password is not correct'))
  })

  void it('POST password change without passing any passwords', async () => {
    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ 'content-type': 'application/json' })
      .send({})

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Password cannot be empty'))
  })

  void it('POST password change with passing wrong repeated password', async () => {
    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ 'content-type': 'application/json' })
      .send({ new: 'foo', repeat: 'bar' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('New and repeated password do not match'))
  })

  void it('POST password change without passing an authorization token', async () => {
    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ 'content-type': 'application/json' })
      .send({ new: 'foo', repeat: 'foo' })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password change with passing unrecognized authorization token', async () => {
    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ Authorization: 'Bearer unknown', 'content-type': 'application/json' })
      .send({ new: 'foo', repeat: 'foo' })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  // Regression test for TC-1304EB9E: the current-password check used to be
  // skipped entirely (`if (currentPassword && ...)`) whenever `current` was
  // omitted, so any valid session token was enough to overwrite the account
  // password without proving knowledge of the existing one.
  void it('rejects a password change that omits the current password, even with a valid session token, and leaves the password unchanged', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'niro-tc1304eb9e@test.com', password: 'OrigPass123!' })
      .expect(201)

    const { token } = await login(app, { email: 'niro-tc1304eb9e@test.com', password: 'OrigPass123!' })

    const res = await request(app)
      .post('/rest/user/change-password')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ new: 'VectorPwn123!', repeat: 'VectorPwn123!' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Current password is not correct'))

    // The original password must still work - the omitted-current bypass
    // must not have mutated anything.
    const stillOriginal = await login(app, { email: 'niro-tc1304eb9e@test.com', password: 'OrigPass123!' })
    assert.ok(stillOriginal.token)
  })

  // Regression test for TC-0F2D5A3F: changing the password used to leave
  // every other outstanding session token for the account fully authorized
  // for its remaining lifetime, so a stolen/leaked token kept working after
  // the legitimate owner "locked out" the attacker by changing the password.
  void it('invalidates other active session tokens for the account when the password is changed', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'niro-tc0f2d5a3f@test.com', password: 'OldPass123!' })
      .expect(201)

    const sessionA = await login(app, { email: 'niro-tc0f2d5a3f@test.com', password: 'OldPass123!' })
    // JWTs are only unique per-second (no jti claim), so log in again a
    // second later to guarantee two genuinely distinct session tokens.
    await new Promise((resolve) => setTimeout(resolve, 1100))
    const sessionB = await login(app, { email: 'niro-tc0f2d5a3f@test.com', password: 'OldPass123!' })
    assert.notEqual(sessionA.token, sessionB.token)

    // Baseline: both sessions can read the account's basket before the change.
    await request(app).get(`/rest/basket/${sessionA.bid}`).set({ Authorization: 'Bearer ' + sessionA.token }).expect(200)
    await request(app).get(`/rest/basket/${sessionB.bid}`).set({ Authorization: 'Bearer ' + sessionB.token }).expect(200)

    // Change the password using only session A.
    const changeRes = await request(app)
      .post('/rest/user/change-password')
      .set({ Authorization: 'Bearer ' + sessionA.token, 'content-type': 'application/json' })
      .send({ current: 'OldPass123!', new: 'NewPass456!', repeat: 'NewPass456!' })
    assert.equal(changeRes.status, 200)

    // The session that performed the change stays authorized (positive control).
    await request(app).get(`/rest/basket/${sessionA.bid}`).set({ Authorization: 'Bearer ' + sessionA.token }).expect(200)

    // Session B was never consulted for the change and must now be rejected.
    await request(app).get(`/rest/basket/${sessionB.bid}`).set({ Authorization: 'Bearer ' + sessionB.token }).expect(401)
  })

  // Regression test for TC-C88B5020: the endpoint used to accept the
  // current/new/repeat passwords as URL query parameters on a GET request,
  // which the global morgan access-log middleware then persisted in
  // plaintext to disk. GET is no longer routed at all, so credentials can no
  // longer travel in the request line.
  void it('no longer accepts a password change via GET with credentials in the query string', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'niro-tcc88b5020@test.com', password: 'InitPass123!' })
      .expect(201)

    const { token } = await login(app, { email: 'niro-tcc88b5020@test.com', password: 'InitPass123!' })

    const res = await request(app)
      .get('/rest/user/change-password?current=InitPass123!&new=VectorTest123!&repeat=VectorTest123!')
      .set({ Authorization: 'Bearer ' + token })

    // GET is no longer a routed method for this endpoint at all, so the
    // request never reaches the handler and the credentials never appear on
    // a route that morgan would log with query-string details.
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected path: /rest/user/change-password'))

    // The password must not have changed.
    const stillOriginal = await login(app, { email: 'niro-tcc88b5020@test.com', password: 'InitPass123!' })
    assert.ok(stillOriginal.token)
  })
})

void describe('/rest/user/reset-password', () => {
  void it('POST password reset for Jim with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'jim@' + config.get<string>('application.domain'),
        answer: 'Samuel',
        new: 'ncc-1701',
        repeat: 'ncc-1701'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Bender with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bender@' + config.get<string>('application.domain'),
        answer: 'Stop\'n\'Drop',
        new: 'OhG0dPlease1nsertLiquor!',
        repeat: 'OhG0dPlease1nsertLiquor!'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Bjoern\u00b4s internal account with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: 'West-2082',
        new: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase',
        repeat: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Bjoern\u00b4s OWASP account with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@owasp.org',
        answer: 'Zaya',
        new: 'kitten lesser pooch karate buffoon indoors',
        repeat: 'kitten lesser pooch karate buffoon indoors'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Morty with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'morty@' + config.get<string>('application.domain'),
        answer: '5N0wb41L',
        new: 'iBurri3dMySe1fInTheB4ckyard!',
        repeat: 'iBurri3dMySe1fInTheB4ckyard!'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset with wrong answer to security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: '25436',
        new: '12345',
        repeat: '12345'
      })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Wrong answer to security question.'))
  })

  void it('POST password reset without any data is blocked', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password reset without new password throws a 401 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: 'W-2082',
        repeat: '12345'
      })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Password cannot be empty.'))
  })

  void it('POST password reset with mismatching passwords throws a 401 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: 'W-2082',
        new: '12345',
        repeat: '1234_'
      })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('New and repeated password do not match.'))
  })

  void it('POST password reset with no email address throws a 412 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        answer: 'W-2082',
        new: 'abcdef',
        repeat: 'abcdef'
      })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password reset with no answer to the security question throws a 412 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        new: 'abcdef',
        repeat: 'abcdef'
      })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })
})
