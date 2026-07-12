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
      // The JWT signing key can be provisioned at runtime (env var, mounted
      // secret, or a freshly generated instance keypair) rather than living in
      // the source tree, so serve the key actually in use instead of a static
      // file that could be stale or absent.
      res.type('text/plain').send(security.publicKey)
      return
    }

    res.sendFile(path.resolve('encryptionkeys/', file))
  }
}
