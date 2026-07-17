/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns/promises'
import { type LookupAddress } from 'node:dns'

// Any server-side "fetch a URL the user supplies" feature (e.g. profile image
// by URL) must not let the destination be an internal-only or otherwise
// disallowed network address — that would let a caller pivot the app server
// into probing loopback/private/link-local/metadata endpoints it cannot reach
// directly (SSRF). This module centralizes that destination check.

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:'])
const MAX_REDIRECTS = 5

export class BlockedDestinationError extends Error {}

function isBlockedIPv4 (address: string): boolean {
  const octets = address.split('.').map(Number)
  if (octets.length !== 4 || octets.some((octet) => Number.isNaN(octet))) {
    return true // unparsable "IPv4" — fail closed
  }
  const [a, b] = octets
  if (a === 127) return true // loopback (127.0.0.0/8)
  if (a === 10) return true // private (10.0.0.0/8)
  if (a === 172 && b >= 16 && b <= 31) return true // private (172.16.0.0/12)
  if (a === 192 && b === 168) return true // private (192.168.0.0/16)
  if (a === 169 && b === 254) return true // link-local / cloud metadata (169.254.0.0/16)
  if (a === 0) return true // "this network" (0.0.0.0/8)
  return false
}

function isBlockedIPv6 (address: string): boolean {
  const normalized = address.toLowerCase()
  if (normalized === '::1' || normalized === '::') return true // loopback / unspecified

  const mappedV4 = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  if (mappedV4 != null) return isBlockedIPv4(mappedV4[1])

  const firstGroup = parseInt(normalized.split(':')[0] || '0', 16)
  if (firstGroup >= 0xfe80 && firstGroup <= 0xfebf) return true // link-local (fe80::/10)
  if (firstGroup >= 0xfc00 && firstGroup <= 0xfdff) return true // unique local (fc00::/7)
  return false
}

/**
 * Actively rejects (throws BlockedDestinationError) only *confirmed* unsafe
 * destinations: a disallowed URL scheme, or a hostname that resolves to a
 * loopback/private/link-local/metadata address. Used before every outbound
 * fetch of a user-supplied URL, including redirect hops, so a caller cannot
 * make the server reach those destinations.
 *
 * A malformed URL or a hostname that simply fails to resolve is left alone
 * (not thrown here) — those aren't SSRF destinations, they're ordinary bad
 * input, and are surfaced by fetch()'s own error handling exactly as before
 * this check existed.
 */
export async function assertSafeDestination (rawUrl: string): Promise<void> {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return
  }

  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    throw new BlockedDestinationError(`Unsupported URL scheme: ${parsed.protocol}`)
  }

  // URL.hostname keeps the brackets around an IPv6 literal (e.g. "[::1]"),
  // but dns.lookup() expects the bare address ("::1") — strip them so a
  // bracketed IPv6 literal doesn't silently dodge resolution (and therefore
  // the block-list check) below.
  const hostname = parsed.hostname.startsWith('[') && parsed.hostname.endsWith(']')
    ? parsed.hostname.slice(1, -1)
    : parsed.hostname

  let addresses: LookupAddress[]
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true })
  } catch {
    return
  }

  for (const { address, family } of addresses) {
    const blocked = family === 6 ? isBlockedIPv6(address) : isBlockedIPv4(address)
    if (blocked) {
      throw new BlockedDestinationError(`Destination address ${address} for host ${parsed.hostname} is not allowed`)
    }
  }
}

/**
 * fetch() a user-supplied URL after validating its destination, and
 * re-validates every redirect hop before following it (fetch()'s default
 * redirect handling would otherwise let a validated initial host redirect
 * to a blocked destination and bypass the check above).
 */
export async function fetchValidatedUrl (initialUrl: string): Promise<Response> {
  let currentUrl = initialUrl
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await assertSafeDestination(currentUrl)
    const response = await fetch(currentUrl, { redirect: 'manual' })
    const location = response.headers.get('location')
    const isRedirect = response.status >= 300 && response.status < 400
    if (isRedirect && location != null) {
      if (hop === MAX_REDIRECTS) {
        throw new BlockedDestinationError('Too many redirects')
      }
      currentUrl = new URL(location, currentUrl).toString()
      continue
    }
    return response
  }
  throw new BlockedDestinationError('Too many redirects')
}
