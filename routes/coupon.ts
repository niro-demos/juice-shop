/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'

export function applyCoupon () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { params } = req
      const id = params.id
      const coupon: string | undefined = params.coupon ? decodeURIComponent(params.coupon) : undefined

      const basket = await BasketModel.findByPk(id)
      if (!basket) {
        next(new Error(`Basket with id=${id} does not exist.`))
        return
      }

      const user = security.authenticatedUsers.from(req)
      if (!user?.bid || Number(user.bid) !== Number(id) || Number(user.data?.id) !== Number(basket.UserId)) {
        res.status(403).json({ status: 'error', error: 'Invalid BasketId' })
        return
      }

      const discount = security.redeemIssuedCoupon(coupon, basket.UserId)
      if (discount) {
        await basket.update({ coupon: coupon?.toString() })
        return res.json({ discount })
      } else {
        await basket.update({ coupon: null })
        return res.status(404).send('Invalid coupon.')
      }
    } catch (error) {
      next(error)
    }
  }
}
