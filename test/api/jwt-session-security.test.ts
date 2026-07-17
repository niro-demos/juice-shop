/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { register, login } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function base64url (input: Buffer | string): string {
  return Buffer.from(input).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function decodeJwtPayload (token: string): any {
  const parts = token.split('.')
  assert.equal(parts.length, 3, `expected a 3-part JWT, got: ${token}`)
  const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'))
}

function forgeRS256Token (payload: any, privateKeyPem: string): string {
  const header = { alg: 'RS256', typ: 'JWT' }
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`
  const signature = crypto.createSign('RSA-SHA256').update(signingInput).sign(privateKeyPem)
  return `${signingInput}.${base64url(signature)}`
}

function forgeHS256Token (payload: any, hmacSecret: string): string {
  const header = { alg: 'HS256', typ: 'JWT' }
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`
  const signature = crypto.createHmac('sha256', hmacSecret).update(signingInput).digest()
  return `${signingInput}.${base64url(signature)}`
}

function forgedAdminClaims () {
  const now = Math.floor(Date.now() / 1000)
  return {
    status: 'success',
    data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' },
    iat: now,
    exp: now + 21600
  }
}

void describe('JWT session-token security', () => {
  void describe('algorithm confusion (TC-3C07B029)', () => {
    void it('rejects an HS256 token HMAC-signed with the published RS256 public key', async () => {
      const pubKeyRes = await request(app).get('/encryptionkeys/jwt.pub')
      assert.equal(pubKeyRes.status, 200)
      const publicKeyPem: string = pubKeyRes.text
      assert.ok(publicKeyPem.includes('PUBLIC KEY'), 'sanity: fetched a PEM public key')

      const forged = forgeHS256Token(forgedAdminClaims(), publicKeyPem)

      const res = await request(app).get('/api/Users').set('Authorization', `Bearer ${forged}`)
      assert.equal(res.status, 401, 'server must reject a token whose alg header it never issues (RS256->HS256 key confusion)')
    })

    void it('control: a real RS256-signed session is still accepted on the same route', async () => {
      const token = security.authorize({ data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' } })
      const res = await request(app).get('/api/Users').set('Authorization', `Bearer ${token}`)
      assert.equal(res.status, 200, 'sanity: a legitimately-issued RS256 token must still be accepted')
    })
  })

  void describe('hardcoded signing key (TC-DCACAB28)', () => {
    // The exact RSA private key that used to be a literal in lib/insecurity.ts,
    // and is therefore public knowledge (published in this open-source
    // project's git history) to anyone who has ever read the source.
    const LEAKED_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

    void it('rejects a token signed with the key formerly hardcoded in source', async () => {
      const forged = forgeRS256Token(forgedAdminClaims(), LEAKED_PRIVATE_KEY)
      const res = await request(app).get('/api/Users').set('Authorization', `Bearer ${forged}`)
      assert.equal(res.status, 401, 'server must reject a token signed with the historically-leaked key, since it must no longer be the deployment signing key')
    })

    void it('the signing key is not a literal committed to lib/insecurity.ts', () => {
      const source = fs.readFileSync(path.resolve(__dirname, '../../lib/insecurity.ts'), 'utf8')
      assert.ok(!source.includes('MIICXAIBAAKBgQDNwqLEe9wgTXCbC7'), 'lib/insecurity.ts must not contain the historically-leaked private key literal')
    })
  })

  void describe('JWT payload confidentiality (TC-8C833A99)', () => {
    void it('does not embed the account password hash in the session token', async () => {
      const email = `jwt-sec-${Date.now()}@juice-sh.op`
      const password = 'Sup3rSecret!' + Date.now()
      await register(app, { email, password })
      const { token } = await login(app, { email, password })

      const payload = decodeJwtPayload(token)
      assert.equal(payload?.data?.email, email, 'sanity: decode path works and payload is populated')
      assert.equal(payload?.data?.password, undefined, 'session token must not embed the account password hash')
    })

    void it('does not embed the raw TOTP secret in the post-2FA session token', async () => {
      const email = `jwt-sec-2fa-${Date.now()}@juice-sh.op`
      const password = 'Sup3rSecret!' + Date.now()
      const totpSecret = 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'
      await register(app, { email, password, totpSecret })
      const { token } = await login(app, { email, password, totpSecret })

      const payload = decodeJwtPayload(token)
      assert.equal(payload?.data?.email, email, 'sanity: decode path works and payload is populated')
      assert.equal(payload?.data?.totpSecret, undefined, 'post-2FA session token must not embed the raw TOTP secret')
      assert.equal(payload?.data?.password, undefined, 'post-2FA session token must not embed the account password hash either')
    })
  })
})
