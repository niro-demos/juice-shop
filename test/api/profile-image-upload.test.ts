/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import path from 'node:path'
import http from 'node:http'
import fs from 'node:fs'
import { type AddressInfo } from 'node:net'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/profile/image/file', () => {
  void it('POST profile image file valid for JPG format', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', file)
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST profile image file invalid type', async () => {
    const file = path.resolve(__dirname, '../files/invalidProfileImageType.docx')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', file)

    assert.equal(res.status, 415)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Profile image upload does not accept this file type'))
  })

  void it('POST profile image file forbidden for anonymous user', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const res = await request(app)
      .post('/profile/image/file')
      .attach('file', file)

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST profile image file rejected for unrecognizable file content', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', Buffer.from('not an image, just plain text content'), 'random.bin')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Illegal file type'))
  })
})

void describe('/profile/image/url', () => {
  void it('POST profile image URL valid for image available online', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'cataas.com/cat')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST profile image URL redirects even for invalid image URL', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'https://notanimage.here/100/100')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST profile image URL forbidden for anonymous user', { skip: 'FIXME runs into "socket hang up"' }, async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .field('imageUrl', 'cataas.com/cat')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST valid image with tampered content length', { skip: 'Fails on CI/CD pipeline' }, async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .set('Content-Length', '42')
      .attach('file', file)
      .redirects(0)

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected end of form'))
  })
})

// These tests exercise the profile-image-by-URL happy/error paths (extension
// detection, non-OK / empty-body fallback) without hitting the real network.
// A real HTTP server can no longer stand in for the "remote" host here: since
// the SSRF fix (see the "(SSRF protection)" suite below) now blocks outbound
// fetches to loopback/private destinations, a mock server bound to
// 127.0.0.1/localhost would itself be rejected. Instead we point at a
// non-blocked, non-routable documentation address (RFC 5737 TEST-NET-3) and
// stub the global fetch so no real network call is made or needed.
void describe('/profile/image/url (with stubbed remote host)', () => {
  const MOCK_HOST = '203.0.113.10'
  let originalFetch: typeof fetch
  let token: string
  let userId: number

  before(async () => {
    const { token: userToken } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    token = userToken
    userId = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).data.id

    const imageBuffer = fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg'))

    originalFetch = globalThis.fetch
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      const requestUrl = typeof input === 'string' ? input : input.toString()
      const { pathname } = new URL(requestUrl)
      if (pathname.includes('non-ok')) {
        return new Response(null, { status: 404 })
      }
      if (pathname.includes('no-body')) {
        return new Response(null, { status: 204 })
      }
      const contentType = pathname.endsWith('.png') ? 'image/png' : 'image/jpeg'
      return new Response(imageBuffer, { status: 200, headers: { 'Content-Type': contentType } })
    }) as typeof fetch
  })

  after(() => {
    globalThis.fetch = originalFetch
  })

  void it('POST with non-OK response falls back to storing URL as profile image', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', `http://${MOCK_HOST}/non-ok.jpg`)
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST with empty-body response (204) falls back to storing URL as profile image', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', `http://${MOCK_HOST}/no-body.jpg`)
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST with valid response writes file and redirects to profile', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', `http://${MOCK_HOST}/photo.jpg`)
      .redirects(0)

    assert.equal(res.status, 302)
    assert.ok(res.headers.location?.endsWith('/profile'))
  })

  void it('POST with PNG URL extension saves file using PNG extension', async () => {
    await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', `http://${MOCK_HOST}/photo.png`)
      .redirects(0)

    assert.ok(
      fs.existsSync(`frontend/dist/frontend/assets/public/images/uploads/${userId}.png`),
      `Expected file frontend/dist/frontend/assets/public/images/uploads/${userId}.png to exist`
    )
  })

  void it('POST with unrecognised URL extension defaults to JPG extension', async () => {
    await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', `http://${MOCK_HOST}/photo.bmp`)
      .redirects(0)

    assert.ok(
      fs.existsSync(`frontend/dist/frontend/assets/public/images/uploads/${userId}.jpg`),
      `Expected file frontend/dist/frontend/assets/public/images/uploads/${userId}.jpg to exist`
    )
  })
})

// Regression coverage for TC-10B885E3 (SSRF): the profile-image-by-URL
// endpoint must not let an authenticated caller force the server to fetch an
// arbitrary destination of their choosing. A real local HTTP server is used
// here (not stubbed) so these tests prove the actual destination-validation
// code path rejects the request before any outbound fetch is attempted.
void describe('/profile/image/url (SSRF protection)', () => {
  let markerServer: http.Server
  let markerPort: number
  let markerHits: number
  let token: string

  before(async () => {
    const { token: userToken } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    token = userToken

    markerHits = 0
    markerServer = http.createServer((req, res) => {
      markerHits++
      res.statusCode = 200
      res.setHeader('Content-Type', 'image/png')
      res.end('SSRF-MARKER')
    })
    await new Promise<void>((resolve) => { markerServer.listen(0, '127.0.0.1', resolve) })
    markerPort = (markerServer.address() as AddressInfo).port
  })

  beforeEach(() => {
    markerHits = 0
  })

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      markerServer.close((err) => { err != null ? reject(err) : resolve() })
    })
  })

  void it('POST with a loopback IP destination is rejected and never fetched', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', `http://127.0.0.1:${markerPort}/marker.png`)
      .redirects(0)

    assert.equal(res.status, 400)
    assert.equal(markerHits, 0, 'server must not have made an outbound request to the loopback destination')
  })

  void it('POST with a "localhost" hostname destination is rejected and never fetched', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', `http://localhost:${markerPort}/marker.png`)
      .redirects(0)

    assert.equal(res.status, 400)
    assert.equal(markerHits, 0, 'server must not have made an outbound request to the loopback destination')
  })

  void it('POST with a non-http(s) scheme is rejected', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'file:///etc/passwd')
      .redirects(0)

    assert.equal(res.status, 400)
  })
})
