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
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import * as db from '../../data/mongodb'
import * as security from '../../lib/insecurity'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let ownBasketId: number

const validCoupon = security.generateCoupon(15)
const outdatedCoupon = security.generateCoupon(20, new Date(2001, 0, 1))
const forgedCoupon = security.generateCoupon(99)

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token, bid } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
    ownBasketId = bid
  },
  { timeout: 60000 }
)

void describe('/rest/basket/:id', () => {
  void it('GET existing basket by id is not allowed via public API', async () => {
    const res = await request(app).get('/rest/basket/1')
    assert.equal(res.status, 401)
  })

  void it('GET empty basket when requesting non-existing basket id', async () => {
    const res = await request(app).get('/rest/basket/4711').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(res.body.data === null || (typeof res.body.data === 'object' && Object.keys(res.body.data).length === 0))
  })

  void it('GET existing basket with contained products by id', async () => {
    // Basket 1 belongs to the admin account (seeded 1:1 with UserId), so it must be
    // fetched as its rightful owner now that basket reads are ownership-scoped.
    const { token: adminToken } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })
    const res = await request(app)
      .get('/rest/basket/1')
      .set({ Authorization: 'Bearer ' + adminToken, 'content-type': 'application/json' })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.id, 1)
    assert.equal(res.body.data.Products.length, 3)
  })

  void it('GET basket should accept forged JWTs', async () => {
    // The unsigned token claims the identity (id: 1, i.e. the admin account, which owns
    // basket 1) without ever knowing the private key -- proving the alg:none forgery
    // still authenticates as a real, resource-owning user under the ownership check.
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ data: { id: 1, email: 'jim@juice-sh.op' }, iat: 1508639612, exp: 9999999999 })).toString('base64url')
    const unsignedToken = `${header}.${payload}.`
    const res = await request(app)
      .get('/rest/basket/1')
      .set({ Authorization: 'Bearer ' + unsignedToken, 'content-type': 'application/json' })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })
})

void describe('/api/Baskets', () => {
  void it('POST new basket is not part of API', async () => {
    const res = await request(app)
      .post('/api/Baskets')
      .set(authHeader)
      .send({ UserId: 1 })
    assert.equal(res.status, 500)
  })

  void it('GET all baskets is not part of API', async () => {
    const res = await request(app).get('/api/Baskets').set(authHeader)
    assert.equal(res.status, 500)
  })
})

void describe('/api/Baskets/:id', () => {
  void it('GET existing basket is not part of API', async () => {
    const res = await request(app).get('/api/Baskets/1').set(authHeader)
    assert.equal(res.status, 500)
  })

  void it('PUT update existing basket is not part of API', async () => {
    const res = await request(app)
      .put('/api/Baskets/1')
      .set(authHeader)
      .send({ UserId: 2 })
    assert.equal(res.status, 500)
  })

  void it('DELETE existing basket is not part of API', async () => {
    const res = await request(app).delete('/api/Baskets/1').set(authHeader)
    assert.equal(res.status, 500)
  })
})

void describe('/rest/basket/:id', () => {
  void it('GET existing basket of another user is forbidden', async () => {
    const { token, bid } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const otherUserAuthHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    // Control: bjoern can read their own basket -- proves the account/session itself is healthy.
    const ownRes = await request(app).get('/rest/basket/' + bid).set(otherUserAuthHeader)
    assert.equal(ownRes.status, 200)
    assert.equal(ownRes.body.data.id, bid)

    // Attack: bjoern must not be able to read jim's basket (id 2) by simply supplying its id.
    const res = await request(app)
      .get('/rest/basket/' + ownBasketId)
      .set(otherUserAuthHeader)
    assert.notEqual(res.status, 200)
  })
})

void describe('/rest/basket/:id/checkout', () => {
  void it('POST placing an order for a basket is not allowed via public API', async () => {
    const res = await request(app).post('/rest/basket/1/checkout')
    assert.equal(res.status, 401)
  })

  void it('POST placing an order for an existing basket returns orderId', async () => {
    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing an order for a non-existing basket fails', async () => {
    const res = await request(app).post('/rest/basket/42/checkout').set(authHeader)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Basket with id=42 does not exist.'))
  })

  void it('POST placing an order for a basket with a negative total cost is possible', async () => {
    const itemRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 10, quantity: -100 })
    assert.equal(itemRes.status, 200)

    const res = await request(app).post('/rest/basket/3/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing an order for a basket with 99% discount is possible', async () => {
    const couponRes = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(forgedCoupon))
      .set(authHeader)
    assert.equal(couponRes.status, 200)
    assert.ok(couponRes.headers['content-type']?.includes('application/json'))
    assert.equal(couponRes.body.discount, 99)

    const res = await request(app).post('/rest/basket/2/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void describe('error cases', () => {
    void it('should return 500 if QuantityModel.findOne fails during checkout', async (t) => {
      const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
      const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
      await request(app).post('/api/BasketItems').set(authHeader).send({ BasketId: 4, ProductId: 1, quantity: 1 })

      t.mock.method(QuantityModel, 'findOne', () => { throw new Error('Quantity error') })
      const res = await request(app).post('/rest/basket/4/checkout').set(authHeader)
      assert.equal(res.status, 500)
      assert.match(res.text, /Quantity error/)
    })

    void it('should return 500 if WalletModel.findOne fails during checkout', async (t) => {
      const { token } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
      const adminAuthHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
      await request(app).post('/api/BasketItems').set(adminAuthHeader).send({ BasketId: 1, ProductId: 1, quantity: 1 })
      t.mock.method(WalletModel, 'findOne', () => { throw new Error('Wallet error') })

      const res = await request(app).post('/rest/basket/1/checkout').set(adminAuthHeader).send({ orderDetails: { paymentId: 'wallet' }, UserId: 1 })
      assert.equal(res.status, 500)
      assert.match(res.text, /Wallet error/)
    })

    void it('should return 500 if ordersCollection.insert fails during checkout', async (t) => {
      const { token } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
      const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
      await request(app).post('/api/BasketItems').set(authHeader).send({ BasketId: 1, ProductId: 1, quantity: 1 })

      t.mock.method(db.ordersCollection, 'insert', async () => { throw new Error('Insert error') })
      const res = await request(app).post('/rest/basket/1/checkout').set(authHeader)
      assert.equal(res.status, 500)
      assert.match(res.text, /Insert error/)
    })
  })
})

void describe('/rest/basket/:id/coupon/:coupon', () => {
  void it('PUT apply valid coupon to existing basket', async () => {
    const res = await request(app)
      .put('/rest/basket/' + ownBasketId + '/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.discount, 15)
  })

  void it('PUT apply invalid coupon is not accepted', async () => {
    const res = await request(app)
      .put('/rest/basket/' + ownBasketId + '/coupon/xxxxxxxxxx')
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply outdated coupon is not accepted', async () => {
    const res = await request(app)
      .put('/rest/basket/' + ownBasketId + '/coupon/' + encodeURIComponent(outdatedCoupon))
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply valid coupon to non-existing basket throws error', async () => {
    const res = await request(app)
      .put('/rest/basket/4711/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 500)
  })

  void it('PUT apply coupon to another user\'s basket is forbidden', async () => {
    const { token } = await login(app, {
      email: 'bender@juice-sh.op',
      password: 'OhG0dPlease1nsertLiquor!'
    })
    const attackerAuthHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const before = await request(app).get('/rest/basket/' + ownBasketId).set(authHeader)
    assert.equal(before.status, 200)
    const couponBeforeAttack = before.body.data.coupon

    const res = await request(app)
      .put('/rest/basket/' + ownBasketId + '/coupon/' + encodeURIComponent(validCoupon))
      .set(attackerAuthHeader)
    assert.notEqual(res.status, 200)

    const after = await request(app).get('/rest/basket/' + ownBasketId).set(authHeader)
    assert.equal(after.status, 200)
    assert.equal(after.body.data.coupon, couponBeforeAttack)
  })
})
