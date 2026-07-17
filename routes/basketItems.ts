/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import { QuantityModel } from '../models/quantity'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const result = utils.parseJsonCustom((req as RequestWithRawBody).rawBody)
    const productIds = []
    const basketIds = []
    const quantities = []

    for (let i = 0; i < result.length; i++) {
      if (result[i].key === 'ProductId') {
        productIds.push(result[i].value)
      } else if (result[i].key === 'BasketId') {
        basketIds.push(result[i].value)
      } else if (result[i].key === 'quantity') {
        quantities.push(result[i].value)
      }
    }

    // A legitimate request never contains more than one BasketId key. Reject outright
    // rather than letting the ownership check and the actual write read different
    // occurrences of a duplicated key (the check must always see the value that gets used).
    if (basketIds.length > 1) {
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
      return
    }

    const resolvedBasketId = basketIds[basketIds.length - 1]
    const user = security.authenticatedUsers.from(req)
    if (user && resolvedBasketId && resolvedBasketId !== 'undefined' && Number(user.bid) != Number(resolvedBasketId)) { // eslint-disable-line eqeqeq
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      const basketItem = {
        ProductId: productIds[productIds.length - 1],
        BasketId: resolvedBasketId,
        quantity: quantities[quantities.length - 1]
      }
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && basketItem.BasketId && basketItem.BasketId !== 'undefined' && user.bid != basketItem.BasketId }) // eslint-disable-line eqeqeq

      const basketItemInstance = BasketItemModel.build(basketItem)
      try {
        const addedBasketItem = await basketItemInstance.save()
        res.json({ status: 'success', data: addedBasketItem })
      } catch (error) {
        next(error)
      }
    }
  }
}

export function getBasketItems () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = security.authenticatedUsers.from(req)
      const items = await BasketItemModel.findAll({ where: { BasketId: user?.bid ?? -1 } })
      res.json({ status: 'success', data: items })
    } catch (error) {
      next(error)
    }
  }
}

export function getBasketItemById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = security.authenticatedUsers.from(req)
      const item = await BasketItemModel.findOne({ where: { id: req.params.id, BasketId: user?.bid ?? -1 } })
      if (item == null) {
        res.status(403).json({ status: 'error', message: 'Malicious activity detected' })
        return
      }
      res.json({ status: 'success', data: item })
    } catch (error) {
      next(error)
    }
  }
}

export function deleteBasketItemById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = security.authenticatedUsers.from(req)
      const item = await BasketItemModel.findOne({ where: { id: req.params.id, BasketId: user?.bid ?? -1 } })
      if (item == null) {
        res.status(403).json({ status: 'error', message: 'Malicious activity detected' })
        return
      }
      await item.destroy()
      res.json({ status: 'success', data: {} })
    } catch (error) {
      next(error)
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    void quantityCheck(req, res, next, req.body.ProductId, req.body.quantity).catch((error: Error) => {
      next(error)
    })
  }
}
export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      const user = security.authenticatedUsers.from(req)
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
      // An item that already belongs to a basket must only be modified by that basket's
      // owner. Items with no basket yet (BasketId null) have no owner to check against.
      if (item != null && item.BasketId != null && (!user || Number(user.bid) !== Number(item.BasketId))) {
        res.status(403).json({ status: 'error', message: 'Malicious activity detected' })
        return
      }
      if (req.body.quantity) {
        if (item == null) {
          throw new Error('No such item found!')
        }
        void quantityCheck(req, res, next, item.ProductId, req.body.quantity)
      } else {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
    if (product.quantity >= quantity) { // enough in stock?
      next()
    } else {
      res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
    }
  } else {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }) })
  }
}
