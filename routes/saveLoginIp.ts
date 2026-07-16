/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import net from 'node:net'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

export function saveLoginIp () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req) ?? req.cookies?.token
    const loggedInUser = security.authenticatedUsers.get(token)
    if (loggedInUser !== undefined) {
      let lastLoginIp = req.headers['true-client-ip']
      if (Array.isArray(lastLoginIp)) {
        lastLoginIp = lastLoginIp[0]
      }
      if (utils.isChallengeEnabled(challenges.httpHeaderXssChallenge)) {
        challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return lastLoginIp === '<iframe src="javascript:alert(`xss`)">' })
      }
      if (lastLoginIp === undefined) {
        lastLoginIp = utils.toSimpleIpAddress(req.socket.remoteAddress ?? '')
      }
      const lastLoginIpString = lastLoginIp.toString()
      if (net.isIP(lastLoginIpString) === 0) {
        res.status(400).send(res.__('Invalid IP address.'))
        return
      }
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        const updatedUser = await user?.update({ lastLoginIp: lastLoginIpString })
        security.authenticatedUsers.remove(token)
        res.clearCookie('token')
        res.json(security.toSafeUser(updatedUser))
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
