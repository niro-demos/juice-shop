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
import * as security from '../../lib/insecurity'

let app: Express

const adminAuthHeader = { Authorization: `Bearer ${security.authorize({ data: { email: 'admin@juice-sh.op' } })}`, 'content-type': 'application/json' }
const attackerAuthHeader = { Authorization: `Bearer ${security.authorize({ data: { email: 'mallory@juice-sh.op' } })}`, 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/products/:id/reviews', () => {
  void it('GET product reviews by product id', async () => {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const review = res.body.data[0]
    assert.equal(typeof review.product, 'number')
    assert.equal(typeof review.message, 'string')
    assert.equal(typeof review.author, 'string')
  })

  void it('GET product reviews attack by injecting a mongoDB sleep command', async () => {
    const res = await request(app)
      .get('/rest/products/sleep(1)/reviews')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })

  // FIXME Turn on when #1960 is resolved
  void it.skip('GET product reviews by alphanumeric non-mongoDB-command product id', async () => {
    const res = await request(app)
      .get('/rest/products/kaboom/reviews')
    assert.equal(res.status, 400)
  })

  void it('PUT single product review can be created', async () => {
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message: 'Lorem Ipsum',
        author: 'Anonymous'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })
})

void describe('/rest/products/reviews', () => {
  let reviewId: string

  before(async () => {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    const response = res.body
    reviewId = response.data[0]._id
  })

  void it('PATCH single product review can be edited by its own author', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(adminAuthHeader)
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.modified, 'number')
    assert.equal(res.body.modified, 1)
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
  })

  void it('PATCH single product review cannot be overwritten by a different authenticated user', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(attackerAuthHeader)
      .send({
        id: reviewId,
        message: 'HACKED BY MALLORY'
      })
    assert.notEqual(res.status, 200)

    const check = await request(app)
      .get('/rest/products/1/reviews')
    const review = check.body.data.find((r: any) => r._id === reviewId)
    assert.notEqual(review.message, 'HACKED BY MALLORY')
  })

  void it('PATCH single product review editing need an authenticated user', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 401)
  })

  void it('POST non-existing product review cannot be liked', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: 'does not exist'
      })
    assert.equal(res.status, 404)
  })

  void it('POST single product review can be liked', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: reviewId
      })
    assert.equal(res.status, 200)
  })

  void it('PATCH multiple product review via NoSQL operator injection is rejected', async () => {
    const injectedMessage = 'trololololololololololololololololololololololololololol'

    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(adminAuthHeader)
      .send({
        id: { $ne: -1 },
        message: injectedMessage
      })
    assert.equal(res.status, 400)

    // confirm no review on any seeded product was mass-overwritten by the operator injection
    for (const productId of [1, 2, 3]) {
      const check = await request(app)
        .get(`/rest/products/${productId}/reviews`)
      const overwritten = check.body.data.filter((r: any) => r.message === injectedMessage)
      assert.equal(overwritten.length, 0)
    }
  })
})
