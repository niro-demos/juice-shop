/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import { AddressModel } from '../models/address'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

export const getRecycleItem = () => (req: Request, res: Response) => {
  const userId = req.body.UserId
  RecycleModel.findAll({
    where: {
      id: JSON.parse(req.params.id),
      UserId: userId
    }
  }).then((Recycle) => {
    if (Recycle.length === 0) {
      return res.status(403).json({ error: 'Forbidden' })
    }
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

export const ensureRecycleAddressBelongsToUser = () => async (req: Request, res: Response, next: NextFunction) => {
  const address = await AddressModel.findOne({ where: { id: req.body.AddressId, UserId: req.body.UserId } })
  if (address == null) {
    res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    return
  }
  next()
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
