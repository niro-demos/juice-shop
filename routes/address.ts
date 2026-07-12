/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ValidationError } from 'sequelize'
import { AddressModel } from '../models/address'

export function getAddress () {
  return async (req: Request, res: Response) => {
    const addresses = await AddressModel.findAll({ where: { UserId: req.body.UserId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

export function putAddressById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address == null) {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
      return
    }
    // Strip UserId/id from the update payload so the caller cannot reassign ownership of the record
    const updateFields = { ...req.body }
    delete updateFields.UserId
    delete updateFields.id
    try {
      const updatedAddress = await address.update(updateFields)
      res.status(200).json({ status: 'success', data: updatedAddress })
    } catch (error) {
      if (error instanceof ValidationError) {
        res.status(400).json({ status: 'error', data: error.message })
        return
      }
      next(error)
    }
  }
}

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}
