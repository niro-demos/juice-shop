/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { challenges } from '../../data/datacache'
import { servePublicFiles } from '../../routes/fileServer'
import { type Challenge } from '@juice-shop/data/types'

void describe('fileServer', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    res = { sendFile: mock.fn(), status: mock.fn() }
    req = { params: {}, query: {} }
    next = mock.fn()
    save = () => ({
      then () { }
    })
  })

  void it('should serve PDF files from folder /ftp', () => {
    req.params.file = 'test.pdf'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 1)
    assert.match(res.sendFile.mock.calls[0].arguments[0], /ftp[/\\]test\.pdf/)
  })

  void it('should serve Markdown files from folder /ftp', () => {
    req.params.file = 'test.md'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 1)
    assert.match(res.sendFile.mock.calls[0].arguments[0], /ftp[/\\]test\.md/)
  })

  void it('should serve incident-support.kdbx files from folder /ftp', () => {
    req.params.file = 'incident-support.kdbx'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 1)
    assert.match(res.sendFile.mock.calls[0].arguments[0], /ftp[/\\]incident-support\.kdbx/)
  })

  void it('should raise error for slashes in filename', () => {
    req.params.file = '../../../../nice.try'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 0)
    assert.equal(next.mock.calls.length, 1)
    assert.ok(next.mock.calls[0].arguments[0] instanceof Error)
  })

  void it('should raise error for disallowed file type', () => {
    req.params.file = 'nice.try'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 0)
    assert.equal(next.mock.calls.length, 1)
    assert.ok(next.mock.calls[0].arguments[0] instanceof Error)
  })

  void it('should solve "directoryListingChallenge" when requesting acquisitions.md', () => {
    challenges.directoryListingChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'acquisitions.md'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 1)
    assert.match(res.sendFile.mock.calls[0].arguments[0], /ftp[/\\]acquisitions\.md/)
    assert.equal(challenges.directoryListingChallenge.solved, true)
  })

  // Regression coverage for TC-471B9F9B: verify() used to check the allowlist
  // against the raw, un-normalized filename and only afterwards cut off the
  // poison-null-byte payload before serving, so a name ending in an allowed
  // extension only *before* normalization (e.g. `package.json.bak%00.md`)
  // passed the check but a different file (`package.json.bak`, which is
  // blocked when requested directly) was the one actually opened. The
  // allowlist must be evaluated against the same string that gets served -
  // so none of these poison-null-byte requests may reach res.sendFile or
  // solve their associated challenge any more.
  void it('should reject "eastere.gg" via Poison Null Byte attack now that the allowlist runs on the normalized filename', () => {
    challenges.easterEggLevelOneChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'eastere.gg%00.md'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 0)
    assert.equal(next.mock.calls.length, 1)
    assert.ok(next.mock.calls[0].arguments[0] instanceof Error)
    assert.equal(challenges.easterEggLevelOneChallenge.solved, false)
  })

  void it('should reject "package.json.bak" via Poison Null Byte attack now that the allowlist runs on the normalized filename', () => {
    challenges.forgottenDevBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'package.json.bak%00.md'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 0)
    assert.equal(next.mock.calls.length, 1)
    assert.ok(next.mock.calls[0].arguments[0] instanceof Error)
    assert.equal(challenges.forgottenDevBackupChallenge.solved, false)
  })

  void it('should reject "coupons_2013.md.bak" via Poison Null Byte attack now that the allowlist runs on the normalized filename', () => {
    challenges.forgottenBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'coupons_2013.md.bak%00.md'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 0)
    assert.equal(next.mock.calls.length, 1)
    assert.ok(next.mock.calls[0].arguments[0] instanceof Error)
    assert.equal(challenges.forgottenBackupChallenge.solved, false)
  })

  void it('should reject "suspicious_errors.yml" via Poison Null Byte attack now that the allowlist runs on the normalized filename', () => {
    challenges.misplacedSignatureFileChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'suspicious_errors.yml%00.md'

    servePublicFiles()(req, res, next)

    assert.equal(res.sendFile.mock.calls.length, 0)
    assert.equal(next.mock.calls.length, 1)
    assert.ok(next.mock.calls[0].arguments[0] instanceof Error)
    assert.equal(challenges.misplacedSignatureFileChallenge.solved, false)
  })
})
