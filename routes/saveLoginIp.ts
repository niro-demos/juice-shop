/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (loggedInUser !== undefined) {
      let lastLoginIp = req.headers['true-client-ip']
      if (Array.isArray(lastLoginIp)) {
        lastLoginIp = lastLoginIp[0]
      }
      if (utils.isChallengeEnabled(challenges.httpHeaderXssChallenge)) {
        challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return lastLoginIp === '<iframe src="javascript:alert(`xss`)">' })
      } else {
        lastLoginIp = security.sanitizeSecure(lastLoginIp ?? '')
      }
      if (lastLoginIp === undefined) {
        lastLoginIp = utils.toSimpleIpAddress(req.socket.remoteAddress ?? '')
      }
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp: lastLoginIp?.toString() })
        // Never echo the raw Sequelize instance back to the caller - it
        // carries the password hash, deluxeToken and totpSecret. Return
        // only the fields the client actually needs.
        res.json({
          id: updatedUser?.id,
          username: updatedUser?.username,
          email: updatedUser?.email,
          role: updatedUser?.role,
          lastLoginIp: updatedUser?.lastLoginIp,
          profileImage: updatedUser?.profileImage,
          isActive: updatedUser?.isActive,
          createdAt: updatedUser?.createdAt,
          updatedAt: updatedUser?.updatedAt,
          deletedAt: updatedUser?.deletedAt
        })
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
