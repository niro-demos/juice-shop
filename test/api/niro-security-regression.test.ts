/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { randomUUID } from 'node:crypto'
import * as utils from '../../lib/utils'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express

const jsonHeader = { 'content-type': 'application/json' }
const denyStatuses = new Set([401, 403, 404])
const leakPattern = /(<pre>|<h1>[^<]*Express|OWASP Juice Shop \(Express|TypeError|URIError|RangeError|ERR_OUT_OF_RANGE|Cannot read properties|URI malformed|Received NaN|\/build\/routes\/|\/routes\/(?:redirect|repeatNotification|videoHandler)\.(?:js|ts):\d+:\d+|\/Users\/)/

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function authHeader (email: string, password: string) {
  const { token } = await login(app, { email, password })
  return { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
}

function userIdFromAuthHeader (header: Record<string, string>) {
  const token = header.Authorization.replace('Bearer ', '')
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'))
  return Number(payload.data.id)
}

function roleFromAuthHeader (header: Record<string, string>) {
  const token = header.Authorization.replace('Bearer ', '')
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'))
  return payload.data.role
}

async function registerActor (label: string) {
  const password = `NiroRegression-${randomUUID()}!`
  const email = `niro-${label}-${randomUUID()}@example.test`
  const res = await register(app, { email, password })
  const header = await authHeader(email, password)
  return { email, password, id: Number(res.body.data.id), header }
}

async function createCaptcha () {
  const res = await request(app).get('/rest/captcha')
  assert.equal(res.status, 200)
  return res.body
}

async function createAddress (owner: { header: Record<string, string> }, label: string) {
  const res = await request(app)
    .post('/api/Addresss')
    .set(owner.header)
    .send({
      fullName: `Niro ${label}`,
      mobileNum: 7100000000,
      zipCode: label.slice(0, 8),
      streetAddress: `${label} Harness Street`,
      city: 'Harness City',
      state: 'CA',
      country: 'USA'
    })

  assert.equal(res.status, 201)
  return res.body.data
}

function assertDenied (res: request.Response) {
  assert.ok(denyStatuses.has(res.status), `expected 401, 403, or 404, got ${res.status}`)
}

function responseText (res: request.Response) {
  return res.text ?? (Buffer.isBuffer(res.body) ? res.body.toString('utf8') : '')
}

void describe('Niro route authorization regressions', () => {
  void it('restricts user records and authentication details to administrators', async () => {
    const admin = await authHeader(`admin@${config.get<string>('application.domain')}`, 'admin123')
    const customer = await authHeader(`jim@${config.get<string>('application.domain')}`, 'ncc-1701')

    const customerUsers = await request(app).get('/api/Users').set(customer)
    assert.equal(customerUsers.status, 403)

    const customerAdminRecord = await request(app).get('/api/Users/1').set(customer)
    assert.equal(customerAdminRecord.status, 403)

    const customerDetails = await request(app).get('/rest/user/authentication-details').set(customer)
    assert.equal(customerDetails.status, 403)

    const adminUsers = await request(app).get('/api/Users').set(admin)
    assert.equal(adminUsers.status, 200)
    assert.ok(adminUsers.body.data.some((user: { email: string, role: string }) => user.email === `admin@${config.get<string>('application.domain')}` && user.role === 'admin'))

    const adminDetails = await request(app).get('/rest/user/authentication-details').set(admin)
    assert.equal(adminDetails.status, 200)
  })

  void it('creates registrations as customers even when a privileged role is supplied', async () => {
    const email = `niro-admin-registration-${randomUUID()}@example.test`
    const password = `NiroRegression-${randomUUID()}!`

    const res = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email,
        password,
        passwordRepeat: password,
        securityQuestion: null,
        securityAnswer: null,
        role: 'admin'
      })

    assert.equal(res.status, 201)
    assert.equal(res.body.data.role, 'customer')

    const header = await authHeader(email, password)
    assert.equal(userIdFromAuthHeader(header), res.body.data.id)
    assert.equal(roleFromAuthHeader(header), 'customer')
  })

  void it('prevents customer and visitor catalog mutations while preserving admin writes', async () => {
    const admin = await authHeader(`admin@${config.get<string>('application.domain')}`, 'admin123')
    const customer = await authHeader(`jim@${config.get<string>('application.domain')}`, 'ncc-1701')

    const anonymousUpdate = await request(app)
      .put('/api/Products/1')
      .set(jsonHeader)
      .send({ price: 0.01 })
    assertDenied(anonymousUpdate)

    const customerCreate = await request(app)
      .post('/api/Products')
      .set(customer)
      .send({
        name: `Niro customer product ${randomUUID()}`,
        description: 'customer mutation proof',
        price: 0.01,
        deluxePrice: 0.01,
        image: 'apple_juice.jpg'
      })
    assert.equal(customerCreate.status, 403)

    const adminCreate = await request(app)
      .post('/api/Products')
      .set(admin)
      .send({
        name: `Niro admin product ${randomUUID()}`,
        description: 'admin positive control',
        price: 0.02,
        deluxePrice: 0.02,
        image: 'apple_juice.jpg'
      })
    assert.equal(adminCreate.status, 201)

    const adminUpdate = await request(app)
      .put(`/api/Products/${adminCreate.body.data.id}`)
      .set(admin)
      .send({ price: 0.03 })
    assert.equal(adminUpdate.status, 200)
    assert.equal(adminUpdate.body.data.price, 0.03)
  })
})

void describe('Niro ownership regressions', () => {
  void it('does not persist visitor-supplied feedback attribution', async () => {
    const anonymousCaptcha = await createCaptcha()
    const anonymousFeedback = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: `Niro anonymous feedback ${randomUUID()}`,
        rating: 3,
        captchaId: anonymousCaptcha.captchaId,
        captcha: anonymousCaptcha.answer
      })
    assert.equal(anonymousFeedback.status, 201)
    assert.equal(anonymousFeedback.body.data.UserId, null)

    const forgedCaptcha = await createCaptcha()
    const forgedFeedback = await request(app)
      .post('/api/Feedbacks')
      .set(jsonHeader)
      .send({
        comment: `Niro forged feedback ${randomUUID()}`,
        rating: 1,
        UserId: 3,
        captchaId: forgedCaptcha.captchaId,
        captcha: forgedCaptcha.answer
      })

    assert.equal(forgedFeedback.status, 201)
    assert.notEqual(forgedFeedback.body.data.UserId, 3)
  })

  void it('binds complaint creation and listing to the authenticated customer', async () => {
    const actorA = await registerActor('complaint-a')
    const actorB = await registerActor('complaint-b')
    const ownMessage = `Niro own complaint ${randomUUID()}`
    const otherMessage = `Niro other complaint ${randomUUID()}`

    const ownComplaint = await request(app)
      .post('/api/Complaints')
      .set(actorA.header)
      .send({ UserId: actorA.id, message: ownMessage })
    assert.equal(ownComplaint.status, 201)
    assert.equal(ownComplaint.body.data.UserId, actorA.id)

    const otherComplaint = await request(app)
      .post('/api/Complaints')
      .set(actorB.header)
      .send({ UserId: actorB.id, message: otherMessage })
    assert.equal(otherComplaint.status, 201)

    const forgedComplaint = await request(app)
      .post('/api/Complaints')
      .set(actorA.header)
      .send({ UserId: actorB.id, message: `Niro forged complaint ${randomUUID()}` })
    assert.equal(forgedComplaint.status, 201)
    assert.equal(forgedComplaint.body.data.UserId, actorA.id)

    const listed = await request(app)
      .get('/api/Complaints')
      .set(actorA.header)
    assert.equal(listed.status, 200)
    assert.ok(listed.body.data.some((complaint: { message: string, UserId: number }) => complaint.message === ownMessage && complaint.UserId === actorA.id))
    assert.ok(!listed.body.data.some((complaint: { message: string, UserId: number }) => complaint.message === otherMessage && complaint.UserId === actorB.id))
  })

  void it('requires authentication for recycle details and rejects foreign recycle ownership', async () => {
    const actorA = await registerActor('recycle-a')
    const actorB = await registerActor('recycle-b')
    const addressA = await createAddress(actorA, 'RecycleA')
    const addressB = await createAddress(actorB, 'RecycleB')

    const legitimate = await request(app)
      .post('/api/Recycles')
      .set(actorA.header)
      .send({
        UserId: actorA.id,
        AddressId: addressA.id,
        quantity: 1,
        isPickup: false,
        date: '2030-01-01'
      })
    assert.equal(legitimate.status, 201)
    assert.equal(legitimate.body.data.UserId, actorA.id)
    assert.equal(legitimate.body.data.AddressId, addressA.id)

    const ownerRead = await request(app)
      .get(`/api/Recycles/${legitimate.body.data.id}`)
      .set(actorA.header)
    assert.equal(ownerRead.status, 200)

    const anonymousRead = await request(app)
      .get(`/api/Recycles/${legitimate.body.data.id}`)
    assertDenied(anonymousRead)

    const foreign = await request(app)
      .post('/api/Recycles')
      .set(actorA.header)
      .send({
        UserId: actorB.id,
        AddressId: addressB.id,
        quantity: 1,
        isPickup: false,
        date: '2030-01-01'
      })
    assert.equal(foreign.status, 403)
  })
})

void describe('Niro public static exposure regressions', () => {
  void it('does not publish support logs', async () => {
    const listing = await request(app).get('/support/logs/')
    assertDenied(listing)
    assert.ok(!responseText(listing).includes('access.log.'))

    const accessLog = await request(app).get('/support/logs/access.log.' + utils.toISO8601(new Date()))
    assertDenied(accessLog)
    assert.ok(!responseText(accessLog).includes('"GET '))
  })

  void it('does not publish encryption keys', async () => {
    const listing = await request(app).get('/encryptionkeys/')
    assertDenied(listing)
    assert.ok(!responseText(listing).includes('premium.key'))

    const premiumKey = await request(app).get('/encryptionkeys/premium.key')
    assertDenied(premiumKey)
    assert.ok(!responseText(premiumKey).includes('1337133713371337'))

    const publicKey = await request(app).get('/encryptionkeys/jwt.pub')
    assertDenied(publicKey)
    assert.ok(!responseText(publicKey).includes('BEGIN PUBLIC KEY'))
  })

  void it('does not publish non-public FTP material', async () => {
    const checks = [
      { path: '/ftp/', markers: ['acquisitions.md', 'incident-support.kdbx', 'quarantine'] },
      { path: '/ftp/acquisitions.md', markers: ['# Planned Acquisitions', 'This document is confidential'] },
      { path: '/ftp/incident-support.kdbx', markers: ['Database', 'KeePass'] },
      { path: '/ftp/quarantine/', markers: ['juicy_malware_windows_64.exe.url'] },
      { path: '/ftp/quarantine/juicy_malware_windows_64.exe.url', markers: ['URL=https://github.com/juice-shop/juicy-malware'] }
    ]

    for (const check of checks) {
      const res = await request(app).get(check.path)
      assertDenied(res)
      for (const marker of check.markers) {
        assert.ok(!responseText(res).includes(marker))
      }
    }
  })
})

void describe('Niro safe error response regressions', () => {
  void it('returns a controlled authorization response for unauthenticated order history', async () => {
    const admin = await authHeader(`admin@${config.get<string>('application.domain')}`, 'admin123')
    const authenticated = await request(app)
      .get('/rest/order-history')
      .set(admin)
    assert.equal(authenticated.status, 200)

    const res = await request(app).get('/rest/order-history')
    assert.ok([401, 403].includes(res.status), `expected 401 or 403, got ${res.status}`)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(!leakPattern.test(responseText(res)))
  })

  void it('keeps malformed auxiliary requests from disclosing implementation details', async () => {
    const controls = [
      { path: '/redirect?to=https://github.com/juice-shop/juice-shop', expectedStatus: 302 },
      { path: '/rest/repeat-notification?challenge=Retrieve%20Blueprint', expectedStatus: 200 },
      { path: '/video', expectedStatus: 206, headers: { Range: 'bytes=0-0' } }
    ]

    for (const control of controls) {
      const res = await request(app)
        .get(control.path)
        .set(control.headers ?? {})
        .redirects(0)
      assert.equal(res.status, control.expectedStatus)
      assert.ok(!leakPattern.test(responseText(res)))
    }

    const probes = [
      { path: '/redirect' },
      { path: '/rest/repeat-notification?challenge=%25' },
      { path: '/video', headers: { Range: 'bytes=garbage' } }
    ]

    for (const probe of probes) {
      const res = await request(app)
        .get(probe.path)
        .set(probe.headers ?? {})
      assert.ok(res.status >= 400, `expected an error response for ${probe.path}`)
      assert.ok(!leakPattern.test(responseText(res)), `${probe.path} leaked implementation details`)
    }
  })
})
