/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express

interface TestUser {
  userId: number
  bid: number
  token: string
  authHeader: { Authorization: string, 'content-type': string }
}

const password = 'NiroAuthzTest1!'

async function createUser (name: string): Promise<TestUser> {
  const email = `authz-${name}-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`
  const registerRes = await register(app, { email, password })
  const auth = await login(app, { email, password })

  return {
    userId: registerRes.body.data.id,
    bid: auth.bid,
    token: auth.token,
    authHeader: {
      Authorization: 'Bearer ' + auth.token,
      'content-type': 'application/json'
    }
  }
}

async function createAddress (user: TestUser) {
  const res = await request(app)
    .post('/api/Addresss')
    .set(user.authHeader)
    .send({
      fullName: 'Authz User',
      mobileNum: '9800000000',
      zipCode: 'NX 101',
      streetAddress: 'Authorization Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
  assert.equal(res.status, 201)
  return res.body.data
}

async function createBasketItem (user: TestUser) {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(user.authHeader)
    .send({ BasketId: user.bid, ProductId: 2, quantity: 1 })
  assert.equal(res.status, 200)
  return res.body.data
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('customer-owned resource authorization', () => {
  void it('rejects cross-customer basket reads, checkout, and item quantity changes', async () => {
    const owner = await createUser('basket-owner')
    const attacker = await createUser('basket-attacker')
    const item = await createBasketItem(owner)

    const ownerUpdate = await request(app)
      .put('/api/BasketItems/' + item.id)
      .set(owner.authHeader)
      .send({ quantity: 2 })
    assert.equal(ownerUpdate.status, 200)
    assert.equal(ownerUpdate.body.data.quantity, 2)

    const attackerRead = await request(app)
      .get('/rest/basket/' + owner.bid)
      .set(attacker.authHeader)
    assert.ok(attackerRead.status === 403 || attackerRead.status === 404)

    const attackerCheckout = await request(app)
      .post('/rest/basket/' + owner.bid + '/checkout')
      .set(attacker.authHeader)
      .send({})
    assert.ok(attackerCheckout.status === 403 || attackerCheckout.status === 404)

    const attackerUpdate = await request(app)
      .put('/api/BasketItems/' + item.id)
      .set(attacker.authHeader)
      .send({ quantity: 3 })
    assert.ok(attackerUpdate.status === 403 || attackerUpdate.status === 404)

    const ownerBasket = await request(app)
      .get('/rest/basket/' + owner.bid)
      .set(owner.authHeader)
    assert.equal(ownerBasket.status, 200)
    const product = ownerBasket.body.data.Products.find((product: any) => product.BasketItem.id === item.id)
    assert.equal(product.BasketItem.quantity, 2)
  })

  void it('rejects cross-customer delivery address updates', async () => {
    const owner = await createUser('address-owner')
    const attacker = await createUser('address-attacker')
    const address = await createAddress(owner)

    const ownerUpdate = await request(app)
      .put('/api/Addresss/' + address.id)
      .set(owner.authHeader)
      .send({ fullName: 'Updated Owner' })
    assert.equal(ownerUpdate.status, 200)
    assert.equal(ownerUpdate.body.data.UserId, owner.userId)

    const attackerUpdate = await request(app)
      .put('/api/Addresss/' + address.id)
      .set(attacker.authHeader)
      .send({ fullName: 'Taken Address' })
    assert.ok(attackerUpdate.status === 400 || attackerUpdate.status === 403)

    const ownerRead = await request(app)
      .get('/api/Addresss/' + address.id)
      .set(owner.authHeader)
    assert.equal(ownerRead.status, 200)
    assert.equal(ownerRead.body.data.UserId, owner.userId)
    assert.equal(ownerRead.body.data.fullName, 'Updated Owner')
  })

  void it('requires authentication and ownership for recycle details', async () => {
    const owner = await createUser('recycle-owner')
    const attacker = await createUser('recycle-attacker')
    const address = await createAddress(owner)

    const createRes = await request(app)
      .post('/api/Recycles')
      .set(owner.authHeader)
      .send({
        UserId: owner.userId,
        AddressId: address.id,
        quantity: 123,
        isPickup: true,
        date: '2270-01-17'
      })
    assert.equal(createRes.status, 201)
    const recycleId = createRes.body.data.id

    const ownerRead = await request(app)
      .get('/api/Recycles/' + recycleId)
      .set(owner.authHeader)
    assert.equal(ownerRead.status, 200)
    assert.ok(ownerRead.body.data.some((item: any) => item.id === recycleId))

    const anonymousRead = await request(app).get('/api/Recycles/' + recycleId)
    assert.ok(anonymousRead.status === 401 || anonymousRead.status === 403)

    const attackerRead = await request(app)
      .get('/api/Recycles/' + recycleId)
      .set(attacker.authHeader)
    assert.ok(attackerRead.status === 403 || attackerRead.status === 404)
  })

  void it('binds submissions to the submitting customer and their resources', async () => {
    const attacker = await createUser('submission-attacker')
    const victim = await createUser('submission-victim')
    const attackerAddress = await createAddress(attacker)
    const victimAddress = await createAddress(victim)

    const captchaRes = await request(app).get('/rest/captcha')
    assert.equal(captchaRes.status, 200)

    const forgedFeedback = await request(app)
      .post('/api/Feedbacks')
      .set({ 'content-type': 'application/json' })
      .send({
        comment: 'anonymous forged feedback',
        rating: 1,
        UserId: victim.userId,
        captchaId: captchaRes.body.captchaId,
        captcha: captchaRes.body.answer
      })
    assert.equal(forgedFeedback.status, 201)
    assert.ok(forgedFeedback.body.data.UserId == null)

    const forgedComplaint = await request(app)
      .post('/api/Complaints')
      .set(attacker.authHeader)
      .send({ message: 'forged complaint', UserId: victim.userId })
    assert.equal(forgedComplaint.status, 201)
    assert.equal(forgedComplaint.body.data.UserId, attacker.userId)

    const ownRecycle = await request(app)
      .post('/api/Recycles')
      .set(attacker.authHeader)
      .send({
        UserId: victim.userId,
        AddressId: attackerAddress.id,
        quantity: 1,
        isPickup: false,
        date: '2026-07-21'
      })
    assert.equal(ownRecycle.status, 201)
    assert.equal(ownRecycle.body.data.UserId, attacker.userId)
    assert.equal(ownRecycle.body.data.AddressId, attackerAddress.id)

    const forgedRecycle = await request(app)
      .post('/api/Recycles')
      .set(attacker.authHeader)
      .send({
        UserId: victim.userId,
        AddressId: victimAddress.id,
        quantity: 1,
        isPickup: false,
        date: '2026-07-21'
      })
    assert.ok(forgedRecycle.status === 400 || forgedRecycle.status === 403)
  })
})
