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

const customer = {
  email: 'bjoern.kimminich@gmail.com',
  password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function getProductReviews (productId = 1) {
  const res = await request(app)
    .get(`/rest/products/${productId}/reviews`)
  assert.equal(res.status, 200)
  assert.ok(Array.isArray(res.body.data))
  return res.body.data
}

async function createReview (token: string, message: string, author = 'spoofed@example.test') {
  const res = await request(app)
    .put('/rest/products/1/reviews')
    .set({ Authorization: `Bearer ${token}` })
    .send({ message, author })
  assert.equal(res.status, 201)
  return res
}

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

  void it('GET product reviews rejects executable product identifiers', async () => {
    const res = await request(app)
      .get('/rest/products/1%20%7C%7C%20sleep(1)/reviews')
    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })

  void it('GET product reviews by alphanumeric product id is rejected', async () => {
    const res = await request(app)
      .get('/rest/products/kaboom/reviews')
    assert.equal(res.status, 400)
  })

  void it('PUT single product review needs an authenticated user', async () => {
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message: 'Lorem Ipsum',
        author: 'Anonymous'
      })
    assert.equal(res.status, 401)
  })

  void it('PUT single product review uses the authenticated user as author', async () => {
    const { token } = await login(app, customer)
    const message = `Authenticated review ${Date.now()}`

    const res = await request(app)
      .put('/rest/products/1/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        message,
        author: 'attacker-controlled@example.test'
      })

    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))

    const created = (await getProductReviews()).find((review: any) => review.message === message)
    assert.equal(created?.author, customer.email)
  })
})

void describe('/rest/products/reviews', () => {
  let token: string
  let reviewId: string
  let otherReviewId: string
  let otherReviewMessage: string

  before(async () => {
    const auth = await login(app, customer)
    token = auth.token

    const ownMessage = `Customer-owned review ${Date.now()}`
    await createReview(token, ownMessage)

    const reviews = await getProductReviews()
    const ownReview = reviews.find((review: any) => review.message === ownMessage)
    const otherReview = reviews.find((review: any) => review._id !== ownReview?._id && review.author !== customer.email)
    assert.ok(ownReview?._id)
    assert.ok(otherReview?._id)

    reviewId = ownReview._id
    otherReviewId = otherReview._id
    otherReviewMessage = otherReview.message
  })

  void it('PATCH own product review can be edited', async () => {
    const message = `Updated owned review ${Date.now()}`
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: reviewId,
        message
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.modified, 1)
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))

    const updated = (await getProductReviews()).find((review: any) => review._id === reviewId)
    assert.equal(updated?.author, customer.email)
    assert.equal(updated?.message, message)
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

  void it('PATCH rejects editing a review written by another user', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: otherReviewId,
        message: 'Cross-owner edit'
      })
    assert.equal(res.status, 403)

    const unchanged = (await getProductReviews()).find((review: any) => review._id === otherReviewId)
    assert.equal(unchanged?.message, otherReviewMessage)
  })

  void it('POST non-existing product review cannot be liked', async () => {
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: 'does not exist'
      })
    assert.equal(res.status, 404)
  })

  void it('POST single product review can be liked', async () => {
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: reviewId
      })
    assert.equal(res.status, 200)
  })

  void it('PATCH rejects selector objects instead of updating multiple reviews', async () => {
    const secondMessage = `Second owned review ${Date.now()}`
    await createReview(token, secondMessage, customer.email)
    const secondReview = (await getProductReviews()).find((review: any) => review.message === secondMessage)
    assert.ok(secondReview?._id)

    const res = await request(app)
      .patch('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: { $in: [reviewId, secondReview._id] },
        message: 'Selector overwrite'
      })
    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))

    const reviews = await getProductReviews()
    assert.notEqual(reviews.find((review: any) => review._id === reviewId)?.message, 'Selector overwrite')
    assert.equal(reviews.find((review: any) => review._id === secondReview._id)?.message, secondMessage)
  })
})
