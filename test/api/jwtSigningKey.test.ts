/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import jwt from 'jsonwebtoken'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express

// This is the RSA private key that used to be hardcoded verbatim as
// `const privateKey = '...'` in lib/insecurity.ts. Anyone with read access to
// the source repository (i.e. anyone, since the repo is public) could copy it
// out and use it to sign RS256 JWTs for any identity, including the built-in
// admin account, without ever supplying a password or OTP. It must never again
// be a key the running application accepts.
const COMPROMISED_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

function forgeAdminToken (privateKeyPem: string): string {
  return jwt.sign(
    {
      data: {
        id: 1,
        email: 'admin@juice-sh.op',
        role: 'admin',
        isActive: true
      },
      bid: 1
    },
    privateKeyPem,
    { expiresIn: '6h', algorithm: 'RS256' }
  )
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('JWT signing key', () => {
  void it('rejects a bearer token signed with the private key formerly hardcoded in source, on an endpoint requiring a valid signature', async () => {
    const forgedToken = forgeAdminToken(COMPROMISED_PRIVATE_KEY)

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set({ Authorization: `Bearer ${forgedToken}` })

    assert.equal(res.status, 401)
  })

  void it('rejects a cookie token signed with the private key formerly hardcoded in source', async () => {
    const forgedToken = forgeAdminToken(COMPROMISED_PRIVATE_KEY)

    const res = await request(app)
      .get('/rest/user/whoami')
      .set('Cookie', [`token=${forgedToken}`])

    assert.equal(res.status, 200)
    // undefined fields are dropped by JSON serialization, so an "empty" user comes
    // back as {} rather than an object with explicit undefined properties
    assert.deepEqual(res.body.user, {})
  })

  void it('control: still accepts a token signed with the application\'s own live signing key', async () => {
    const legitimateToken = security.authorize({
      data: { id: 1, email: 'admin@juice-sh.op', role: 'admin', isActive: true }
    })

    const res = await request(app)
      .get('/rest/user/authentication-details')
      .set({ Authorization: `Bearer ${legitimateToken}` })

    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data) && res.body.data.length > 0)
  })
})
