/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as utils from '../../lib/utils'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

// Regression coverage for TC-CF1432B8: /support/logs used to be served by an
// unauthenticated directory listing (serveIndex) plus an open file server
// (serveLogFiles()), guarded only by verify.accessControlChallenges() -
// which is pure telemetry that always calls next() and never blocks. Any
// anonymous visitor could list and download server log files, exposing
// every past visitor's source IP, full request URLs (including query
// strings), User-Agent, and the server's internal absolute file paths.
//
// The invariant: server-side log files must not be listable or downloadable
// by an unauthenticated visitor. There is no legitimate reason to expose
// them through a public URL, so both routes are removed outright; requests
// now fall through to the same SPA shell every other unknown path gets.
void describe('/support/logs/:file', () => {
  void it('GET access log file for the current day no longer returns log content', async () => {
    const res = await request(app)
      .get('/support/logs/access.log.' + utils.toISO8601(new Date()))

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(!res.headers['content-type']?.includes('application/octet-stream'))
    assert.ok(res.text.includes('scripts.js'))
  })

  void it('GET /support/logs no longer serves a directory listing', async () => {
    const res = await request(app)
      .get('/support/logs')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(!res.text.includes('<title>listing directory /support/logs</title>'))
    assert.ok(res.text.includes('scripts.js'))
  })
})
