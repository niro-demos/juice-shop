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
let authHeader: { Authorization: string, 'content-type': string }
let addressId: string

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
  },
  { timeout: 60000 }
)

void describe('/api/Addresss', () => {
  void it('GET all addresses is forbidden via public API', async () => {
    const res = await request(app).get('/api/Addresss')
    assert.equal(res.status, 401)
  })

  void it('GET all addresses', async () => {
    const res = await request(app).get('/api/Addresss').set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('POST new address with all valid fields', async () => {
    const res = await request(app).post('/api/Addresss').set(authHeader).send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 101',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 201)
  })

  void it('POST new address with invalid pin code', async () => {
    const res = await request(app).post('/api/Addresss').set(authHeader).send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 10111111',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 400)
  })

  void it('POST new address with invalid mobile number', async () => {
    const res = await request(app).post('/api/Addresss').set(authHeader).send({
      fullName: 'Jim',
      mobileNum: '10000000000',
      zipCode: 'NX 101',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 400)
  })

  void it('POST new address is forbidden via public API', async () => {
    const res = await request(app).post('/api/Addresss').send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 10111111',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 401)
  })
})

void describe('/api/Addresss/:id', () => {
  before(async () => {
    const res = await request(app).post('/api/Addresss').set(authHeader).send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 101',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 201)
    addressId = res.body.data.id
  })

  void it('GET address by id is forbidden via public API', async () => {
    const res = await request(app).get('/api/Addresss/' + addressId)
    assert.equal(res.status, 401)
  })

  void it('PUT update address is forbidden via public API', async () => {
    const res = await request(app)
      .put('/api/Addresss/' + addressId)
      .set({ 'content-type': 'application/json' })
      .send({ quantity: 2 })
    assert.equal(res.status, 401)
  })

  void it('DELETE address by id is forbidden via public API', async () => {
    const res = await request(app).delete('/api/Addresss/' + addressId)
    assert.equal(res.status, 401)
  })

  void it('GET address by id', async () => {
    const res = await request(app)
      .get('/api/Addresss/' + addressId)
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('GET address by non-existing id returns 400 for authorized user', async () => {
    const nonExistingId = 999999
    const res = await request(app)
      .get('/api/Addresss/' + nonExistingId)
      .set(authHeader)
    assert.equal(res.status, 400)
    assert.equal(res.body.status, 'error')
    assert.equal(res.body.data, 'Malicious activity detected.')
  })

  void it('PUT update address by id', async () => {
    const res = await request(app)
      .put('/api/Addresss/' + addressId)
      .set(authHeader)
      .send({ fullName: 'Jimy' })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.fullName, 'Jimy')
  })

  void it('PUT update address by id with invalid mobile number is forbidden', async () => {
    const res = await request(app)
      .put('/api/Addresss/' + addressId)
      .set(authHeader)
      .send({ mobileNum: '10000000000' })
    assert.equal(res.status, 400)
  })

  void it('PUT update address by id with invalid pin code is forbidden', async () => {
    const res = await request(app)
      .put('/api/Addresss/' + addressId)
      .set(authHeader)
      .send({ zipCode: 'NX 10111111' })
    assert.equal(res.status, 400)
  })

  void it('DELETE address by id', async () => {
    const res = await request(app)
      .delete('/api/Addresss/' + addressId)
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('DELETE address by id again returns 400 for authorized user', async () => {
    const res = await request(app)
      .delete('/api/Addresss/' + addressId)
      .set(authHeader)
    assert.equal(res.status, 400)
    assert.equal(res.body.status, 'error')
    assert.equal(res.body.data, 'Malicious activity detected.')
  })
})

void describe('/api/Addresss/:id cross-account ownership', () => {
  let ownerAddressId: string
  let attackerAuthHeader: { Authorization: string, 'content-type': string }

  before(async () => {
    const res = await request(app).post('/api/Addresss').set(authHeader).send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 101',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
    assert.equal(res.status, 201)
    ownerAddressId = res.body.data.id

    const { token } = await login(app, {
      email: 'bender@juice-sh.op',
      password: 'OhG0dPlease1nsertLiquor!'
    })
    attackerAuthHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
  })

  void it('PUT by a non-owner must not overwrite or steal another customer\'s address', async () => {
    const res = await request(app)
      .put('/api/Addresss/' + ownerAddressId)
      .set(attackerAuthHeader)
      .send({
        fullName: 'HACKED by attacker',
        mobileNum: '9800000000',
        zipCode: 'NX 101',
        streetAddress: 'Pwned Street 1',
        city: 'Pwned City',
        state: 'X',
        country: 'X'
      })
    assert.notEqual(res.status, 200)

    const check = await request(app)
      .get('/api/Addresss/' + ownerAddressId)
      .set(authHeader)
    assert.equal(check.status, 200)
    assert.equal(check.body.data.fullName, 'Jim')
    assert.equal(check.body.data.streetAddress, 'Bakers Street')

    const ownerList = await request(app).get('/api/Addresss').set(authHeader)
    assert.ok(ownerList.body.data.some((address: { id: string }) => String(address.id) === String(ownerAddressId)))
  })
})
