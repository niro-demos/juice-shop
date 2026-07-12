/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'

export function getComplaints () {
  return async (req: Request, res: Response) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    const isAdmin = loggedInUser?.data?.role === security.roles.admin
    const where = isAdmin ? {} : { UserId: loggedInUser?.data?.id ?? -1 }
    const complaints = await ComplaintModel.findAll({ where })
    res.status(200).json({ status: 'success', data: complaints })
  }
}
