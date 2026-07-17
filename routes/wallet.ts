/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { CardModel } from '../models/card'

export function getWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
    if (wallet != null) {
      res.status(200).json({ status: 'success', data: wallet.balance })
    } else {
      res.status(404).json({ status: 'error' })
    }
  }
}

// Same bound the client already advertises (wallet.component.ts Validators.min(10)/max(1000)),
// enforced server-side so it cannot be bypassed by calling the API directly. There is no real
// payment gateway integration behind this top-up, so this is the strongest charge-amount check
// available: an amount outside this range can never legitimately come from the client-side form.
const MIN_TOP_UP_AMOUNT = 10
const MAX_TOP_UP_AMOUNT = 1000

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const balance = req.body.balance
    if (typeof balance !== 'number' || !Number.isFinite(balance) || balance < MIN_TOP_UP_AMOUNT || balance > MAX_TOP_UP_AMOUNT) {
      res.status(400).json({ status: 'error', message: `Balance must be a number between ${MIN_TOP_UP_AMOUNT} and ${MAX_TOP_UP_AMOUNT}.` })
      return
    }
    const cardId = req.body.paymentId
    const card = cardId ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null
    if (card != null) {
      try {
        await WalletModel.increment({ balance }, { where: { UserId: req.body.UserId } })
        res.status(200).json({ status: 'success', data: balance })
      } catch {
        res.status(404).json({ status: 'error' })
      }
    } else {
      res.status(402).json({ status: 'error', message: 'Payment not accepted.' })
    }
  }
}
