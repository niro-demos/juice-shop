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

// This is the exact RSA private key that used to be hardcoded verbatim as
// `const privateKey = '...'` in lib/insecurity.ts. Because the source is
// public, anyone could copy this key out of the repository and use it to
// forge RS256-signed session tokens for ANY user id/role -- including
// admin -- entirely offline, without ever authenticating. It must never
// again be a key that the running application accepts as valid.
const COMPROMISED_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

function forgeToken (id: number, email: string, role: string): string {
  return jwt.sign(
    {
      status: 'success',
      data: {
        id,
        email,
        role,
        username: '',
        password: 'FORGED-BY-TEST',
        deluxeToken: '',
        lastLoginIp: '0.0.0.0',
        profileImage: '/assets/public/images/uploads/default.svg',
        isActive: true,
        createdAt: '2020-01-01T00:00:00.000Z',
        updatedAt: '2020-01-01T00:00:00.000Z',
        deletedAt: null
      }
    },
    COMPROMISED_PRIVATE_KEY,
    { expiresIn: '6h', algorithm: 'RS256' }
  )
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('Hardcoded JWT signing key', () => {
  void it('control: rejects requests with no token at all (auth gate is alive)', async () => {
    const res = await request(app).get('/api/Users')
    assert.equal(res.status, 401)
  })

  void it('rejects an admin token forged offline with the key formerly hardcoded in lib/insecurity.ts', async () => {
    const forgedAdminToken = forgeToken(1, 'admin@juice-sh.op', 'admin')

    const usersRes = await request(app)
      .get('/api/Users')
      .set('Authorization', `Bearer ${forgedAdminToken}`)
    assert.equal(usersRes.status, 401)

    const userRes = await request(app)
      .get('/api/Users/1')
      .set('Authorization', `Bearer ${forgedAdminToken}`)
    assert.equal(userRes.status, 401)

    const detailsRes = await request(app)
      .get('/rest/user/authentication-details')
      .set('Authorization', `Bearer ${forgedAdminToken}`)
    assert.equal(detailsRes.status, 401)
  })

  void it('rejects a forged token impersonating an arbitrary existing user id', async () => {
    const forgedToken = forgeToken(2, 'jim@juice-sh.op', 'customer')

    const res = await request(app)
      .get('/api/Users/2')
      .set('Authorization', `Bearer ${forgedToken}`)
    assert.equal(res.status, 401)
  })

  void it('control: still accepts a token signed with the application\'s own live signing key', async () => {
    const legitimateToken = security.authorize({
      data: { id: 1, email: 'admin@juice-sh.op', role: 'admin', isActive: true }
    })

    const res = await request(app)
      .get('/api/Users')
      .set('Authorization', `Bearer ${legitimateToken}`)
    assert.equal(res.status, 200)
  })
})
