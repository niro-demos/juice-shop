/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let jimToken: string
let jimBasketId: number
let benderToken: string
let benderBasketId: number
let adminToken: string

const jsonHeader = { 'content-type': 'application/json' }

function auth (token: string) {
  return { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}

function assertNoAuthSecrets (value: unknown) {
  const text = JSON.stringify(value)
  assert.ok(!text.includes('"password"'), 'response must not contain password fields')
  assert.ok(!text.includes('"totpSecret"'), 'response must not contain two-factor secrets')
  assert.ok(!text.includes('"deluxeToken"'), 'response must not contain deluxe tokens')
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  const jim = await login(app, {
    email: `jim@${config.get<string>('application.domain')}`,
    password: 'ncc-1701'
  })
  jimToken = jim.token
  jimBasketId = jim.bid

  const bender = await login(app, {
    email: `bender@${config.get<string>('application.domain')}`,
    password: 'OhG0dPlease1nsertLiquor!'
  })
  benderToken = bender.token
  benderBasketId = bender.bid

  const admin = await login(app, {
    email: `admin@${config.get<string>('application.domain')}`,
    password: 'admin123'
  })
  adminToken = admin.token
}, { timeout: 60000 })

void describe('security hardening regressions', () => {
  void it('rejects catalog mutation by unauthenticated visitors and standard customers', async () => {
    const unauthenticatedUpdate = await request(app)
      .put('/api/Products/1')
      .set(jsonHeader)
      .send({ description: '<iframe src="javascript:alert(`xss`)"></iframe>' })
    assert.ok([401, 403].includes(unauthenticatedUpdate.status))

    const customerCreate = await request(app)
      .post('/api/Products')
      .set(auth(jimToken))
      .send({
        name: 'Customer controlled product',
        description: 'not allowed',
        price: 1,
        deluxePrice: 1,
        image: 'apple_juice.jpg'
      })
    assert.ok([401, 403].includes(customerCreate.status))

    const adminCreate = await request(app)
      .post('/api/Products')
      .set(auth(adminToken))
      .send({
        name: 'Admin controlled product',
        description: 'allowed',
        price: 1,
        deluxePrice: 1,
        image: 'apple_juice.jpg'
      })
    assert.ok([200, 201].includes(adminCreate.status))
  })

  void it('rejects administrator role assignment during public registration', async () => {
    const res = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'role-escalation@example.test',
        password: 'not-admin',
        role: 'admin'
      })
    assert.ok([200, 201].includes(res.status))
    assert.equal(res.body.data.role, 'customer')
  })

  void it('does not authenticate SQL-shaped login input', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({
        email: "' OR 1=1--",
        password: 'anything'
      })
    assert.equal(res.status, 401)
  })

  void it('keeps authentication secrets out of tokens and current-user responses', async () => {
    const payload = security.decode(jimToken)
    assertNoAuthSecrets(payload)

    const whoami = await request(app)
      .get('/rest/user/whoami?fields=id,email,password,totpSecret,deluxeToken')
      .set({ Cookie: `token=${jimToken}` })
    assert.equal(whoami.status, 200)
    assertNoAuthSecrets(whoami.body)

    const savedIp = await request(app)
      .get('/rest/saveLoginIp')
      .set({ Authorization: `Bearer ${jimToken}`, 'True-Client-IP': '198.51.100.10' })
    assert.equal(savedIp.status, 200)
    assertNoAuthSecrets(savedIp.body)
  })

  void it('restricts user directory endpoints to administrators without secret fields', async () => {
    const customerList = await request(app).get('/api/Users').set(auth(jimToken))
    assert.ok([401, 403].includes(customerList.status))

    const customerDetails = await request(app).get('/api/Users/1').set(auth(jimToken))
    assert.ok([401, 403].includes(customerDetails.status))

    const adminList = await request(app).get('/api/Users').set(auth(adminToken))
    assert.equal(adminList.status, 200)
    assertNoAuthSecrets(adminList.body)
  })

  void it('treats catalog search criteria as data instead of SQL', async () => {
    const res = await request(app)
      .get('/rest/products/search')
      .query({ q: "')) UNION SELECT * FROM Users--" })
    assert.equal(res.status, 200)
    assertNoAuthSecrets(res.body)
    assert.ok(Array.isArray(res.body.data))
    assert.equal(res.body.data.some((item: Record<string, unknown>) => item.email || item.password), false)
  })

  void it('enforces basket ownership on reads, writes, coupons, and checkout', async () => {
    const benderItem = await request(app)
      .post('/api/BasketItems')
      .set(auth(benderToken))
      .send({ BasketId: benderBasketId, ProductId: 1, quantity: 1 })
    assert.ok([200, 201].includes(benderItem.status))

    const readOtherBasket = await request(app)
      .get(`/rest/basket/${benderBasketId}`)
      .set(auth(jimToken))
    assert.ok([401, 403, 404].includes(readOtherBasket.status))

    const ambiguousWrite = await request(app)
      .post('/api/BasketItems')
      .set(auth(jimToken))
      .set('content-type', 'application/json')
      .send(`{"BasketId":${jimBasketId},"ProductId":1,"quantity":1,"BasketId":${benderBasketId}}`)
    assert.ok([400, 401, 403].includes(ambiguousWrite.status))

    const updateOtherItem = await request(app)
      .put(`/api/BasketItems/${benderItem.body.data.id}`)
      .set(auth(jimToken))
      .send({ quantity: 2 })
    assert.ok([401, 403, 404].includes(updateOtherItem.status))

    const coupon = security.generateCoupon(10)
    const couponOtherBasket = await request(app)
      .put(`/rest/basket/${benderBasketId}/coupon/${encodeURIComponent(coupon)}`)
      .set(auth(jimToken))
    assert.ok([401, 403, 404].includes(couponOtherBasket.status))

    const checkoutOtherBasket = await request(app)
      .post(`/rest/basket/${benderBasketId}/checkout`)
      .set(auth(jimToken))
      .send({ orderDetails: { paymentId: 'wallet' }, UserId: 2 })
    assert.ok([401, 403, 404].includes(checkoutOtherBasket.status))
  })

  void it('rejects negative basket quantities', async () => {
    const res = await request(app)
      .post('/api/BasketItems')
      .set(auth(jimToken))
      .send({ BasketId: jimBasketId, ProductId: 1, quantity: -100 })
    assert.ok([400, 422].includes(res.status))
  })

  void it('requires verified payment details for wallet credits and deluxe upgrades', async () => {
    const walletCredit = await request(app)
      .put('/rest/wallet/balance')
      .set(auth(jimToken))
      .send({ UserId: 2, paymentId: 1, balance: 100000 })
    assert.ok([402, 403].includes(walletCredit.status))

    const deluxe = await request(app)
      .post('/rest/deluxe-membership')
      .set(auth(jimToken))
      .send({ UserId: 2, paymentMode: 'free' })
    assert.ok([400, 402, 403].includes(deluxe.status))
  })

  void it('does not allow public reset-secret creation or account enumeration', async () => {
    const answer = await request(app)
      .post('/api/SecurityAnswers')
      .set(jsonHeader)
      .send({ UserId: 1, SecurityQuestionId: 1, answer: 'owned' })
    assert.ok([401, 403].includes(answer.status))

    const known = await request(app)
      .get('/rest/user/security-question')
      .query({ email: `jim@${config.get<string>('application.domain')}` })
    const unknown = await request(app)
      .get('/rest/user/security-question')
      .query({ email: 'missing@example.test' })
    assert.equal(known.status, 200)
    assert.equal(unknown.status, 200)
    assert.deepEqual(known.body, unknown.body)
  })

  void it('does not disclose challenge answers to clients', async () => {
    const captcha = await request(app).get('/rest/captcha')
    assert.equal(captcha.status, 200)
    assert.equal(captcha.body.answer, undefined)

    const imageCaptcha = await request(app)
      .get('/rest/image-captcha')
      .set(auth(jimToken))
    assert.equal(imageCaptcha.status, 200)
    assert.equal(imageCaptcha.body.answer, undefined)
  })

  void it('rejects unsafe public file, key, log, and data-erasure reads', async () => {
    const recycle = await request(app).get('/api/Recycles/1')
    assert.ok([401, 403].includes(recycle.status))

    const keyListing = await request(app).get('/encryptionkeys')
    assert.ok([401, 403, 404].includes(keyListing.status))

    const keyFile = await request(app).get('/encryptionkeys/jwt.pub')
    assert.ok([401, 403, 404].includes(keyFile.status))

    const logListing = await request(app).get('/support/logs')
    assert.ok([401, 403, 404].includes(logListing.status))

    const dataErasure = await request(app)
      .post('/dataerasure')
      .set({ Cookie: `token=${jimToken}`, 'content-type': 'application/x-www-form-urlencoded' })
      .send('layout=package.json&email=jim%40juice-sh.op&securityAnswer=Samuel')
    assert.notEqual(dataErasure.status, 200)
  })

  void it('rejects NoSQL-shaped order tracking and review selectors', async () => {
    const order = await request(app).get("/rest/track-order/' || true || '")
    assert.ok([400, 404].includes(order.status) || order.body.data.length <= 1)

    const reviews = await request(app).get('/rest/products/sleep(1000)/reviews')
    assert.ok([400, 404].includes(reviews.status))

    const update = await request(app)
      .patch('/rest/products/reviews')
      .set(auth(jimToken))
      .send({ id: { $ne: null }, message: 'mass update' })
    assert.ok([400, 403].includes(update.status))
  })
})
