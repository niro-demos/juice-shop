/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'

const orderIdPattern = /^[0-9a-f]{4}-[0-9a-f]{16}$/i

export function trackOrder () {
  return (req: Request, res: Response) => {
    const id = String(req.params.id)
    if (!orderIdPattern.test(id)) {
      res.status(400).json({ error: 'Wrong Param' })
      return
    }

    db.ordersCollection.find({ orderId: id }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
