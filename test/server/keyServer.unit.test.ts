/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { serveKeyFiles } from '../../routes/keyServer'
import * as security from '../../lib/insecurity'

void describe('keyServer', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { params: { } }
    res = { sendFile: mock.fn(), status: mock.fn(), type: mock.fn(() => res), send: mock.fn() }
    next = mock.fn()
  })

  void it('should serve requested file from folder /encryptionkeys', () => {
    req.params.file = 'test.file'

    serveKeyFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 1)
    assert.match(res.sendFile.mock.calls[0].arguments[0], /encryptionkeys[/\\]test.file/)
  })

  void it('should raise error for slashes in filename', () => {
    req.params.file = '../../../../nice.try'

    serveKeyFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 0)
    assert.equal(next.mock.calls.length, 1)
    assert.ok(next.mock.calls[0].arguments[0] instanceof Error)
  })

  void it('should serve the live in-memory public key for jwt.pub instead of reading it from disk', () => {
    req.params.file = 'jwt.pub'

    serveKeyFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 0)
    assert.equal(res.send.mock.calls.length, 1)
    assert.equal(res.send.mock.calls[0].arguments[0], security.publicKey)
  })
})
