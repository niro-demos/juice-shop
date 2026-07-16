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
import * as security from '../../lib/insecurity'

let app: Express

const denialStatuses = new Set([401, 403, 404])

interface TestCustomer {
  email: string
  password: string
  token: string
  basketId: number
  authHeader: { Authorization: string, 'content-type': string }
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function uniqueEmail (label: string) {
  return `${label}-${Date.now()}-${Math.random().toString(16).slice(2)}@juice-sh.op`
}

async function createCustomer (label: string): Promise<TestCustomer> {
  const email = uniqueEmail(label)
  const password = `${label}-NiroProof-2026!`

  await register(app, { email, password })
  const auth = await login(app, { email, password })
  assert.ok(typeof auth.token === 'string' && auth.token.length > 0)
  assert.ok(Number.isInteger(auth.bid))

  return {
    email,
    password,
    token: auth.token,
    basketId: auth.bid,
    authHeader: {
      Authorization: 'Bearer ' + auth.token,
      'content-type': 'application/json'
    }
  }
}

async function deleteBasketItem (customer: TestCustomer, itemId?: number) {
  if (itemId != null) {
    await request(app)
      .delete('/api/BasketItems/' + itemId)
      .set(customer.authHeader)
  }
}

async function walletBalance (customer: TestCustomer) {
  let lastResponse: request.Response | undefined
  for (let attempt = 0; attempt < 20; attempt++) {
    lastResponse = await request(app)
      .get('/rest/wallet/balance')
      .set(customer.authHeader)
    if (lastResponse.status === 200) {
      return Number(lastResponse.body.data)
    }
    await new Promise(resolve => setTimeout(resolve, 50))
  }
  assert.fail(`wallet balance was not available: ${lastResponse?.status} ${lastResponse?.text}`)
}

async function orderHistory (customer: TestCustomer) {
  const res = await request(app)
    .get('/rest/order-history')
    .set(customer.authHeader)

  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data
}

function assertDenied (res: request.Response, message: string) {
  assert.ok(denialStatuses.has(res.status), `${message}: got HTTP ${res.status} ${res.text}`)
}

void describe('basket ownership and checkout integrity', () => {
  void it('denies cross-customer basket reads while own basket reads work', async () => {
    const customerA = await createCustomer('basket-owner-a')
    const customerB = await createCustomer('basket-owner-b')

    const ownA = await request(app).get('/rest/basket/' + customerA.basketId).set(customerA.authHeader)
    assert.equal(ownA.status, 200)
    assert.equal(ownA.body.data.id, customerA.basketId)

    const ownB = await request(app).get('/rest/basket/' + customerB.basketId).set(customerB.authHeader)
    assert.equal(ownB.status, 200)
    assert.equal(ownB.body.data.id, customerB.basketId)

    const bReadsA = await request(app).get('/rest/basket/' + customerA.basketId).set(customerB.authHeader)
    const aReadsB = await request(app).get('/rest/basket/' + customerB.basketId).set(customerA.authHeader)

    assertDenied(bReadsA, 'customer B must not read customer A basket')
    assertDenied(aReadsB, 'customer A must not read customer B basket')
  })

  void it('denies cross-customer basket item reads and updates while owner access works', async () => {
    const customerA = await createCustomer('basket-item-a')
    const customerB = await createCustomer('basket-item-b')
    let itemId: number | undefined

    try {
      const createRes = await request(app)
        .post('/api/BasketItems')
        .set(customerB.authHeader)
        .send({ BasketId: customerB.basketId, ProductId: 2, quantity: 1 })
      assert.equal(createRes.status, 200)
      itemId = createRes.body.data.id

      const ownRead = await request(app).get('/api/BasketItems/' + itemId).set(customerB.authHeader)
      assert.equal(ownRead.status, 200)
      assert.equal(ownRead.body.data.BasketId, customerB.basketId)

      const ownUpdate = await request(app)
        .put('/api/BasketItems/' + itemId)
        .set(customerB.authHeader)
        .send({ quantity: 2 })
      assert.equal(ownUpdate.status, 200)
      assert.equal(ownUpdate.body.data.quantity, 2)

      const crossRead = await request(app).get('/api/BasketItems/' + itemId).set(customerA.authHeader)
      const crossUpdate = await request(app)
        .put('/api/BasketItems/' + itemId)
        .set(customerA.authHeader)
        .send({ quantity: 100 })

      assertDenied(crossRead, 'customer A must not read customer B basket item')
      assertDenied(crossUpdate, 'customer A must not update customer B basket item')

      const ownerVerify = await request(app).get('/api/BasketItems/' + itemId).set(customerB.authHeader)
      assert.equal(ownerVerify.status, 200)
      assert.notEqual(ownerVerify.body.data.quantity, 3)
    } finally {
      await deleteBasketItem(customerB, itemId)
    }
  })

  void it('authorizes the persisted BasketId when adding basket items', async () => {
    const attacker = await createCustomer('duplicate-basket-attacker')
    const victim = await createCustomer('duplicate-basket-victim')
    let ownItemId: number | undefined
    let exploitItemId: number | undefined

    try {
      const ownAdd = await request(app)
        .post('/api/BasketItems')
        .set(attacker.authHeader)
        .send({ BasketId: attacker.basketId, ProductId: 2, quantity: 1 })
      assert.equal(ownAdd.status, 200)
      ownItemId = ownAdd.body.data.id

      const ordinaryForeign = await request(app)
        .post('/api/BasketItems')
        .set(attacker.authHeader)
        .send({ BasketId: victim.basketId, ProductId: 1, quantity: 1 })
      assertDenied(ordinaryForeign, 'ordinary cross-basket add must be denied')

      const duplicateBasketIdBody = `{"BasketId":${attacker.basketId},"BasketId":${victim.basketId},"ProductId":1,"quantity":1}`
      const exploit = await request(app)
        .post('/api/BasketItems')
        .set(attacker.authHeader)
        .type('application/json')
        .send(duplicateBasketIdBody)
      exploitItemId = exploit.body?.data?.id

      assertDenied(exploit, 'duplicate BasketId request must be denied')

      const victimBasket = await request(app).get('/rest/basket/' + victim.basketId).set(victim.authHeader)
      assert.equal(victimBasket.status, 200)
      const products = victimBasket.body.data.Products ?? []
      assert.ok(!products.some((product: any) => product.BasketItem?.id === exploitItemId))
    } finally {
      await deleteBasketItem(attacker, ownItemId)
      await deleteBasketItem(victim, exploitItemId)
    }
  })

  void it('rejects negative basket item quantities before checkout', async () => {
    const customer = await createCustomer('negative-quantity')
    let positiveItemId: number | undefined
    let updateItemId: number | undefined

    try {
      const positive = await request(app)
        .post('/api/BasketItems')
        .set(customer.authHeader)
        .send({ BasketId: customer.basketId, ProductId: 1, quantity: 1 })
      assert.equal(positive.status, 200)
      positiveItemId = positive.body.data.id

      const negativeAdd = await request(app)
        .post('/api/BasketItems')
        .set(customer.authHeader)
        .send({ BasketId: customer.basketId, ProductId: 3, quantity: -1 })
      assert.equal(negativeAdd.status, 400)

      const updateSeed = await request(app)
        .post('/api/BasketItems')
        .set(customer.authHeader)
        .send({ BasketId: customer.basketId, ProductId: 4, quantity: 1 })
      assert.equal(updateSeed.status, 200)
      updateItemId = updateSeed.body.data.id

      const negativeUpdate = await request(app)
        .put('/api/BasketItems/' + updateItemId)
        .set(customer.authHeader)
        .send({ quantity: -1 })
      assert.equal(negativeUpdate.status, 400)
    } finally {
      await deleteBasketItem(customer, positiveItemId)
      await deleteBasketItem(customer, updateItemId)
    }
  })

  void it('rejects checkout without payment and does not create an order', async () => {
    const customer = await createCustomer('checkout-payment')
    const beforeOrders = await orderHistory(customer)

    const item = await request(app)
      .post('/api/BasketItems')
      .set(customer.authHeader)
      .send({ BasketId: customer.basketId, ProductId: 1, quantity: 1 })
    assert.equal(item.status, 200)

    const unpaid = await request(app)
      .post('/rest/basket/' + customer.basketId + '/checkout')
      .set(customer.authHeader)
      .send({})
    assert.ok(unpaid.status >= 400, `checkout without payment returned HTTP ${unpaid.status} ${unpaid.text}`)
    assert.equal(unpaid.body.orderConfirmation, undefined)

    const afterOrders = await orderHistory(customer)
    assert.equal(afterOrders.length, beforeOrders.length)

    await deleteBasketItem(customer, item.body.data.id)
  })

  void it('does not credit wallet balance from a saved card without completed charge proof', async () => {
    const customer = await createCustomer('wallet-credit')
    const initialBalance = await walletBalance(customer)

    const noCardCredit = await request(app)
      .put('/rest/wallet/balance')
      .set(customer.authHeader)
      .send({ balance: 13 })
    assert.equal(noCardCredit.status, 402)
    assert.equal(await walletBalance(customer), initialBalance)

    const card = await request(app)
      .post('/api/Cards')
      .set(customer.authHeader)
      .send({
        fullName: 'Wallet Credit Test',
        cardNum: 4111111111111111,
        expMonth: 1,
        expYear: 2091
      })
    assert.equal(card.status, 201)

    const credit = await request(app)
      .put('/rest/wallet/balance')
      .set(customer.authHeader)
      .send({ paymentId: card.body.data.id, balance: 13 })
    assert.ok(credit.status >= 400, `wallet credit without charge proof returned HTTP ${credit.status} ${credit.text}`)
    assert.equal(await walletBalance(customer), initialBalance)

    await request(app).delete('/api/Cards/' + card.body.data.id).set(customer.authHeader)
  })

  void it('rejects unrecognized deluxe membership payment modes', async () => {
    const customer = await createCustomer('deluxe-payment-mode')

    const startingStatus = await request(app).get('/rest/deluxe-membership').set(customer.authHeader)
    assert.equal(startingStatus.status, 200)
    assert.equal(startingStatus.body.data.membershipCost, 49)

    const insufficientWallet = await request(app)
      .post('/rest/deluxe-membership')
      .set(customer.authHeader)
      .send({ paymentMode: 'wallet' })
    assert.equal(insufficientWallet.status, 400)

    const invalidMode = await request(app)
      .post('/rest/deluxe-membership')
      .set(customer.authHeader)
      .send({ paymentMode: 'unrecognized' })
    assert.equal(invalidMode.status, 400)

    const finalStatus = await request(app).get('/rest/deluxe-membership').set(customer.authHeader)
    assert.equal(finalStatus.status, 200)
  })

  void it('rejects self-generated basket coupons', async () => {
    const customer = await createCustomer('forged-coupon')

    const invalid = await request(app)
      .put('/rest/basket/' + customer.basketId + '/coupon/xxxxxxxxxx')
      .set(customer.authHeader)
    assert.equal(invalid.status, 404)

    const forgedCoupon = security.generateCoupon(99)
    const forged = await request(app)
      .put('/rest/basket/' + customer.basketId + '/coupon/' + encodeURIComponent(forgedCoupon))
      .set(customer.authHeader)
    assert.ok(forged.status >= 400, `self-generated coupon returned HTTP ${forged.status} ${forged.text}`)

    const basket = await request(app).get('/rest/basket/' + customer.basketId).set(customer.authHeader)
    assert.equal(basket.status, 200)
    assert.notEqual(basket.body.data.coupon, forgedCoupon)
  })
})
