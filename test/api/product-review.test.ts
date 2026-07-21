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

const adminEmail = 'admin@juice-sh.op'
const benderEmail = 'bender@juice-sh.op'
const authHeader = (email = adminEmail) => ({
  Authorization: `Bearer ${security.authorize({ data: { id: email, email } })}`,
  'content-type': 'application/json'
})

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

  void it('PUT single product review can be created by an authenticated user', async () => {
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set(authHeader())
      .send({
        message: 'Lorem Ipsum',
        author: adminEmail
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })

  void it('PUT product review rejects unauthenticated author spoofing', async () => {
    const message = 'Unauthenticated forged review'
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message,
        author: adminEmail
      })
    assert.equal(res.status, 401)

    const reviews = await request(app)
      .get('/rest/products/1/reviews')
    assert.equal(reviews.status, 200)
    assert.equal(reviews.body.data.some((review: any) => review.message === message && review.author === adminEmail), false)
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

  void it('PATCH single product review can be edited', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader())
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.modified, 'number')
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
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

  void it('PATCH single product review cannot edit another customer review', async () => {
    const victimMessage = 'Victim review original'
    const tamperedMessage = 'Victim review tampered'
    const createRes = await request(app)
      .put('/rest/products/1/reviews')
      .set(authHeader(adminEmail))
      .send({
        message: victimMessage,
        author: adminEmail
      })
    assert.equal(createRes.status, 201)

    const reviewsBefore = await request(app)
      .get('/rest/products/1/reviews')
    assert.equal(reviewsBefore.status, 200)
    const victimReview = reviewsBefore.body.data.find((review: any) => review.message === victimMessage && review.author === adminEmail)
    assert.ok(victimReview?._id)

    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader(benderEmail))
      .send({
        id: victimReview._id,
        message: tamperedMessage
      })
    assert.ok(res.status === 403 || res.status === 404)

    const reviewsAfter = await request(app)
      .get('/rest/products/1/reviews')
    assert.equal(reviewsAfter.status, 200)
    assert.ok(reviewsAfter.body.data.some((review: any) => review._id === victimReview._id && review.message === victimMessage && review.author === adminEmail))
    assert.equal(reviewsAfter.body.data.some((review: any) => review._id === victimReview._id && review.message === tamperedMessage), false)
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

  void it('PATCH multiple product review via injection', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader())
      .send({
        id: { $ne: -1 },
        message: 'trololololololololololololololololololololololololololol'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.modified, 'number')
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
    assert.ok(res.body.modified > 1)
    assert.equal(res.body.modified, res.body.original.length)
  })
})
