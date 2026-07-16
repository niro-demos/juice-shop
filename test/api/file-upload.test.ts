/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import path from 'node:path'
import fs from 'node:fs'
import { randomUUID } from 'node:crypto'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'
import { createTestApp } from './helpers/setup'

let app: Express

function crc32 (buffer: Buffer) {
  let crc = 0xffffffff
  for (const byte of buffer) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1))
    }
  }
  return (crc ^ 0xffffffff) >>> 0
}

function zipOneFile (name: string, content: string) {
  const nameBuffer = Buffer.from(name)
  const contentBuffer = Buffer.from(content)
  const checksum = crc32(contentBuffer)

  const local = Buffer.alloc(30)
  local.writeUInt32LE(0x04034b50, 0)
  local.writeUInt16LE(20, 4)
  local.writeUInt16LE(0, 6)
  local.writeUInt16LE(0, 8)
  local.writeUInt16LE(0, 10)
  local.writeUInt16LE(0, 12)
  local.writeUInt32LE(checksum, 14)
  local.writeUInt32LE(contentBuffer.length, 18)
  local.writeUInt32LE(contentBuffer.length, 22)
  local.writeUInt16LE(nameBuffer.length, 26)
  local.writeUInt16LE(0, 28)

  const central = Buffer.alloc(46)
  central.writeUInt32LE(0x02014b50, 0)
  central.writeUInt16LE(20, 4)
  central.writeUInt16LE(20, 6)
  central.writeUInt16LE(0, 8)
  central.writeUInt16LE(0, 10)
  central.writeUInt16LE(0, 12)
  central.writeUInt16LE(0, 14)
  central.writeUInt32LE(checksum, 16)
  central.writeUInt32LE(contentBuffer.length, 20)
  central.writeUInt32LE(contentBuffer.length, 24)
  central.writeUInt16LE(nameBuffer.length, 28)
  central.writeUInt16LE(0, 30)
  central.writeUInt16LE(0, 32)
  central.writeUInt16LE(0, 34)
  central.writeUInt16LE(0, 36)
  central.writeUInt32LE(0, 38)
  central.writeUInt32LE(0, 42)

  const centralSize = central.length + nameBuffer.length
  const localSize = local.length + nameBuffer.length + contentBuffer.length
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(0, 4)
  end.writeUInt16LE(0, 6)
  end.writeUInt16LE(1, 8)
  end.writeUInt16LE(1, 10)
  end.writeUInt32LE(centralSize, 12)
  end.writeUInt32LE(localSize, 16)
  end.writeUInt16LE(0, 20)

  return Buffer.concat([local, nameBuffer, contentBuffer, central, nameBuffer, end])
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/file-upload', () => {
  void it('POST file valid PDF for client and API', async () => {
    const file = path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file too large for client validation but valid for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidSizeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file with illegal type for client validation but valid for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidTypeForClient.exe')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 204)
  })

  void it('POST file type XML deprecated for API', async () => {
    const file = path.resolve(__dirname, '../files/deprecatedTypeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
  })

  void it('POST file type XML with external entity does not disclose server-local files', async () => {
    const benignRes = await request(app)
      .post('/file-upload')
      .attach('file', Buffer.from('<?xml version="1.0"?><x>control</x>'), {
        filename: 'control.xml',
        contentType: 'application/xml'
      })

    assert.equal(benignRes.status, 410)
    assert.equal(benignRes.text.includes('# Planned Acquisitions'), false)
    assert.equal(benignRes.text.includes('This document is confidential! Do not distribute!'), false)

    const xxe = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY x SYSTEM "ftp/acquisitions.md">]><x>&x;</x>'
    const res = await request(app)
      .post('/file-upload')
      .attach('file', Buffer.from(xxe), {
        filename: 'xxe.xml',
        contentType: 'application/xml'
      })

    assert.equal(res.status, 410)
    assert.equal(res.text.includes('# Planned Acquisitions'), false)
    assert.equal(res.text.includes('This document is confidential! Do not distribute!'), false)
  })

  void it('POST large XML file near upload size limit', async () => {
    const file = path.resolve(__dirname, '../files/maxSizeForServer.xml')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 410)
  })

  if (utils.isChallengeEnabled(challenges.xxeFileDisclosureChallenge) || utils.isChallengeEnabled(challenges.xxeDosChallenge)) {
    void it('POST file type XML with XXE attack against Windows', async () => {
      const file = path.resolve(__dirname, '../files/xxeForWindows.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
    })

    void it('POST file type XML with XXE attack against Linux', async () => {
      const file = path.resolve(__dirname, '../files/xxeForLinux.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
    })

    void it('POST file type XML with Billion Laughs attack is caught by parser', async () => {
      const file = path.resolve(__dirname, '../files/xxeBillionLaughs.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.equal(res.status, 410)
      assert.equal(res.text.includes('Maximum entity amplification factor exceeded'), false)
    })

    void it('POST file type XML with Quadratic Blowup attack', async () => {
      const file = path.resolve(__dirname, '../files/xxeQuadraticBlowup.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.ok(res.status >= 410)
    })

    void it('POST file type XML with dev/random attack', async () => {
      const file = path.resolve(__dirname, '../files/xxeDevRandom.xml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.ok(res.status >= 410)
    })
  }

  if (utils.isChallengeEnabled(challenges.yamlBombChallenge)) {
    void it('POST file type YAML with Billion Laughs-style attack', async () => {
      const file = path.resolve(__dirname, '../files/yamlBomb.yml')
      const res = await request(app)
        .post('/file-upload')
        .attach('file', file)
      assert.ok(res.status >= 410)
    })
  }

  void it('POST file too large for API', async () => {
    const file = path.resolve(__dirname, '../files/invalidSizeForServer.pdf')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 500)
  })

  void it('POST zip file with directory traversal payload is rejected without writing a public FTP file', async () => {
    const fileName = `zip-traversal-${randomUUID()}.md`
    const ftpPath = path.resolve('ftp', fileName)
    const marker = `archive traversal marker ${fileName}\n`

    try {
      const controlRes = await request(app)
        .post('/file-upload')
        .attach('file', zipOneFile(`control-${fileName}`, 'control\n'), {
          filename: `control-${fileName}.zip`,
          contentType: 'application/zip'
        })

      assert.equal(controlRes.status, 204)
      assert.equal(fs.existsSync(ftpPath), false)

      const res = await request(app)
        .post('/file-upload')
        .attach('file', zipOneFile(`../../ftp/${fileName}`, marker), {
          filename: `traversal-${fileName}.zip`,
          contentType: 'application/zip'
        })

      assert.equal(res.status, 400)
      assert.equal(fs.existsSync(ftpPath), false)

      const publicRes = await request(app)
        .get(`/ftp/${fileName}`)

      assert.equal(publicRes.status, 404)
    } finally {
      fs.rmSync(ftpPath, { force: true })
    }
  })

  void it('POST zip file with password protection', async () => {
    const file = path.resolve(__dirname, '../files/passwordProtected.zip')
    const res = await request(app)
      .post('/file-upload')
      .attach('file', file)
    assert.equal(res.status, 500)
  })

  void it('POST valid file with tampered content length', { skip: 'Fails on CI/CD pipeline' }, async () => {
    const file = path.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf')
    const res = await request(app)
      .post('/file-upload')
      .set('Content-Length', '42')
      .attach('file', file)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected end of form'))
  })
})
