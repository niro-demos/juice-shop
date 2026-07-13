/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    if (file === 'jwt.pub') {
      // Served from the live in-memory public key (lib/insecurity.ts) rather
      // than the static file checked into encryptionkeys/, so the key this
      // route intentionally exposes (public keys are not sensitive - this
      // underpins the "Forged Signed JWT" challenge) always matches whichever
      // key pair is actually verifying tokens in this process, regardless of
      // whether it came from JWT_PRIVATE_KEY/JWT_PUBLIC_KEY or was generated
      // at startup.
      res.type('text/plain').send(security.publicKey)
      return
    }

    res.sendFile(path.resolve('encryptionkeys/', file))
  }
}
