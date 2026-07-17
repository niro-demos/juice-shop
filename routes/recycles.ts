/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export const getRecycleItem = () => (req: Request, res: Response) => {
  const id = Number(req.params.id)
  if (!Number.isInteger(id)) {
    return res.status(400).send('Invalid id')
  }

  const user = security.authenticatedUsers.from(req)
  if (user?.data?.id === undefined) {
    return res.status(401).send('Unauthorized')
  }

  RecycleModel.findAll({
    where: {
      id,
      UserId: user.data.id // scope to the authenticated caller so no one can read another user's recycle record
    }
  }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
