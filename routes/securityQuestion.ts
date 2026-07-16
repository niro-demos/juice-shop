/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
export function securityQuestion () {
  return async (_req: Request, res: Response, next: NextFunction) => {
    try {
      res.json({})
    } catch (error) {
      next(error)
    }
  }
}
