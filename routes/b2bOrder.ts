/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    const orderLinesData = body.orderLinesData
    // `orderLinesData` is documented (swagger.yml) as a JSON-encoded string of
    // order lines. It must only ever be parsed as inert data — never
    // evaluated as code (no `eval`/`vm`/"safe eval" sandbox, which are never
    // actually safe against the `Function` constructor).
    if (orderLinesData !== undefined && orderLinesData !== null && orderLinesData !== '') {
      if (typeof orderLinesData !== 'string') {
        res.status(400)
        next(new Error('orderLinesData must be a JSON-encoded string'))
        return
      }
      try {
        JSON.parse(orderLinesData)
      } catch (err) {
        res.status(400)
        next(new Error('orderLinesData must be valid JSON'))
        return
      }
    }
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
