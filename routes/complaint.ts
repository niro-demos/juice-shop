/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ComplaintModel } from '../models/complaint'

export function getComplaints () {
  return async (req: Request, res: Response) => {
    const complaints = await ComplaintModel.findAll({ where: { UserId: req.body.UserId } })
    res.status(200).json({ status: 'success', data: complaints })
  }
}
