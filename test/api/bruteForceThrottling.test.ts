/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import { createTestApp } from './helpers/setup'

// Number of requests fired in a single burst. Must comfortably exceed the
// configured rate-limit `max` of 100 requests per 5-minute window so the
// limiter has a chance to trip.
const BURST = 105

void describe('/rest/user/login brute-force throttling', () => {
  void it('throttles rapid repeated wrong-password attempts against the same account', async () => {
    const { app } = await createTestApp()

    const email = `throttle-login-${Date.now()}@test.rest`
    const password = 'Str0ngP@ssw0rd!23'

    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email, password })
      .expect(201)

    // Positive control: a legitimate login succeeds before the attack starts,
    // proving the environment is healthy.
    const baseline = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email, password })
    assert.equal(baseline.status, 200, 'legitimate login must succeed before the attack (healthy baseline)')

    const statuses: number[] = []
    for (let i = 0; i < BURST; i++) {
      const res = await request(app)
        .post('/rest/user/login')
        .set({ 'content-type': 'application/json' })
        .send({ email, password: `wrong-guess-${i}` })
      statuses.push(res.status)
    }

    assert.ok(
      statuses.includes(429),
      `expected the login endpoint to throttle with a 429 at some point during ${BURST} rapid wrong-password attempts, ` +
      `but every response was one of: ${JSON.stringify([...new Set(statuses)])}`
    )
  }, { timeout: 60000 })
}, { timeout: 60000 })

void describe('/rest/user/reset-password brute-force throttling', () => {
  void it('throttles rapid repeated wrong-answer attempts from a consistent client (baseline)', async () => {
    const { app } = await createTestApp()
    const email = `throttle-reset-baseline-${Date.now()}@juice-sh.op`

    const statuses: number[] = []
    for (let i = 0; i < BURST; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json' })
        .send({ email, answer: `wrong-answer-${i}`, new: 'N3wPassw0rd!', repeat: 'N3wPassw0rd!' })
      statuses.push(res.status)
    }

    assert.ok(
      statuses.includes(429),
      `expected the reset-password limiter to engage (429) for a consistent client identity within ${BURST} requests, ` +
      `but every response was one of: ${JSON.stringify([...new Set(statuses)])}. The limiter itself appears broken, ` +
      'independent of any header-spoofing bypass.'
    )
  }, { timeout: 60000 })

  void it('is not bypassed by sending a distinct spoofed X-Forwarded-For header per request', async () => {
    const { app } = await createTestApp()
    const email = `throttle-reset-attack-${Date.now()}@juice-sh.op`

    const statuses: number[] = []
    for (let i = 0; i < BURST; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({
          'content-type': 'application/json',
          'X-Forwarded-For': `10.1.2.${i % 255}`
        })
        .send({ email, answer: `wrong-answer-${i}`, new: 'N3wPassw0rd!', repeat: 'N3wPassw0rd!' })
      statuses.push(res.status)
    }

    assert.ok(
      statuses.includes(429),
      `expected the reset-password limiter to still engage (429) within ${BURST} requests even though each request ` +
      `carried a distinct spoofed X-Forwarded-For header, but every response was one of: ${JSON.stringify([...new Set(statuses)])}. ` +
      'This means an attacker can claim a different source IP on every request to bypass the throttle entirely.'
    )
  }, { timeout: 60000 })
})
