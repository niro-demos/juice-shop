/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { assertSafeDestination, BlockedDestinationError } from '../../lib/ssrfGuard'

async function isBlocked (url: string): Promise<boolean> {
  try {
    await assertSafeDestination(url)
    return false
  } catch (error) {
    assert.ok(error instanceof BlockedDestinationError, `expected a BlockedDestinationError for ${url}, got ${String(error)}`)
    return true
  }
}

void describe('ssrfGuard', () => {
  void describe('assertSafeDestination', () => {
    void it('blocks loopback IPv4 addresses', async () => {
      assert.equal(await isBlocked('http://127.0.0.1/x'), true)
      assert.equal(await isBlocked('http://127.255.255.255/x'), true)
    })

    void it('blocks the "localhost" hostname', async () => {
      assert.equal(await isBlocked('http://localhost/x'), true)
    })

    void it('blocks IPv6 loopback', async () => {
      assert.equal(await isBlocked('http://[::1]/x'), true)
    })

    void it('blocks RFC1918 private ranges', async () => {
      assert.equal(await isBlocked('http://10.0.0.5/x'), true)
      assert.equal(await isBlocked('http://172.16.0.5/x'), true)
      assert.equal(await isBlocked('http://172.31.255.255/x'), true)
      assert.equal(await isBlocked('http://192.168.1.1/x'), true)
    })

    void it('does not block addresses just outside the private 172.16.0.0/12 range', async () => {
      assert.equal(await isBlocked('http://172.15.255.255/x'), false)
      assert.equal(await isBlocked('http://172.32.0.0/x'), false)
    })

    void it('blocks the link-local / cloud metadata range', async () => {
      assert.equal(await isBlocked('http://169.254.169.254/x'), true)
    })

    void it('rejects non-http(s) schemes', async () => {
      assert.equal(await isBlocked('file:///etc/passwd'), true)
      assert.equal(await isBlocked('ftp://example.com/x'), true)
      assert.equal(await isBlocked('gopher://127.0.0.1/x'), true)
    })

    void it('does not block a public IPv4 address', async () => {
      assert.equal(await isBlocked('http://93.184.216.34/x'), false)
    })

    void it('does not throw on a malformed URL (left to the caller\'s own fetch to surface)', async () => {
      await assertSafeDestination('not-a-url-at-all')
    })

    void it('does not throw when the hostname cannot be resolved', async () => {
      await assertSafeDestination('http://this-host-should-not-resolve.invalid/x')
    })
  })
})
