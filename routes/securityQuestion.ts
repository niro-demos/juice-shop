/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export function securityQuestion () {
  return async ({ query }: Request, res: Response, next: NextFunction) => {
    try {
      if (query.email === undefined) {
        throw new Error('WHERE parameter "email" has invalid "undefined" value')
      }
      res.json({})
    } catch (error) {
      next(error)
    }
  }
}
