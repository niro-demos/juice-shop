/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from '@juice-shop/models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

// The RSA key pair that signs session tokens must be a secret unique to this
// deployment. Prefer an operator-provisioned key (JWT_PRIVATE_KEY /
// JWT_PRIVATE_KEY_PATH, e.g. sourced from a secret manager); if none is
// configured, generate a fresh key pair for this process instead of falling
// back to a value shipped in source -- a hardcoded literal would be
// identical, and known, across every install of this open-source project
// (see TC-DCACAB28). Tradeoff: without an operator-provided key, sessions
// do not survive a process restart, and multiple instances behind a load
// balancer must be given the same JWT_PRIVATE_KEY to share sessions.
function loadOrGenerateJwtKeyPair (): { privateKey: string, publicKey: string } {
  const configuredPrivateKey = process.env.JWT_PRIVATE_KEY ??
    (process.env.JWT_PRIVATE_KEY_PATH ? fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH, 'utf8') : undefined)

  if (configuredPrivateKey !== undefined && configuredPrivateKey !== '') {
    const derivedPublicKey = crypto.createPublicKey(configuredPrivateKey).export({ type: 'pkcs1', format: 'pem' }).toString()
    return { privateKey: configuredPrivateKey, publicKey: derivedPublicKey }
  }

  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' }
  })
}

const jwtKeyPair = loadOrGenerateJwtKeyPair()
export const publicKey = jwtKeyPair.publicKey
const privateKey = jwtKeyPair.privateKey

// GET /encryptionkeys/jwt.pub (routes/keyServer.ts) intentionally serves this
// key to clients so they can verify RS256 tokens themselves -- keep the file
// on disk in sync with whatever key this process actually resolved above, so
// the endpoint never serves a stale key left over from a previous run (e.g.
// before an operator-provided JWT_PRIVATE_KEY was rotated in). Not fatal if
// the filesystem is read-only; the in-memory publicKey export above is what
// actually matters for verification.
try {
  fs.writeFileSync('encryptionkeys/jwt.pub', publicKey)
} catch (error) {
  console.warn('Could not write encryptionkeys/jwt.pub -- GET /encryptionkeys/jwt.pub may serve a stale key', error)
}

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

const JWT_ALGORITHM = 'RS256'
const SENSITIVE_USER_FIELDS = ['password', 'totpSecret']

// jsonwebtoken@0.4.0 (pinned intentionally for the knownVulnerableComponentChallenge)
// and the express-jwt@0.1.3 middleware built on it never restrict which
// algorithm a token may be verified with -- they always trust whatever `alg`
// the token's own header claims, and neither exposes an `algorithms`
// allowlist to configure. That lets an attacker who has the (intentionally
// public) RS256 verification key present an HS256 token HMAC-signed with
// that same key text and have it accepted as if it were a real RS256
// signature ("key confusion", TC-3C07B029). Pin the algorithm here, at the
// application layer, before any signature check runs.
const hasAllowedAlgorithm = (token: string): boolean => {
  try {
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString('utf8'))
    return header?.alg === JWT_ALGORITHM
  } catch {
    return false
  }
}

export const isAuthorized = () => {
  const verifyRS256Signature = expressJwt(({ secret: publicKey }) as any)
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req)
    if (token !== undefined && !hasAllowedAlgorithm(token)) {
      res.status(401).json({ status: 'error', message: 'jwt signature algorithm is not allowed' })
      return
    }
    verifyRS256Signature(req, res, next)
  }
}
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)

// A bearer JWT is only base64url-encoded and signature-protected, never
// encrypted -- anyone holding the token can read its payload with no key at
// all (browser storage, history, proxies, XSS). Never let the account's
// password hash or raw TOTP seed ride along in that client-held payload
// (TC-8C833A99). Both remain available server-side via the DB row and the
// `authenticatedUsers` map, which each call site populates separately (with
// the full user object) from what gets signed here.
const claimsForToken = (payload: any) => {
  if (payload == null || typeof payload !== 'object' || payload.data == null || typeof payload.data !== 'object') {
    return payload
  }
  const data = JSON.parse(JSON.stringify(payload.data))
  for (const field of SENSITIVE_USER_FIELDS) {
    delete data[field]
  }
  return { ...payload, data }
}

export const authorize = (user = {}) => jwt.sign(claimsForToken(user), privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => token && hasAllowedAlgorithm(token) ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token && hasAllowedAlgorithm(token) && authenticatedUsers.get(token) === undefined) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null && decoded?.data !== undefined) {
        authenticatedUsers.put(token, decoded)
        res.cookie('token', token)
      }
    })
  }
  next()
}
