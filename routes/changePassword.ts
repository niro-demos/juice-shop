/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function changePassword () {
  return async ({ body, headers, connection }: Request, res: Response, next: NextFunction) => {
    const currentPassword = body.current as string
    const newPassword = body.new as string
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = body.repeat

    if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }

    const token = headers.authorization ? headers.authorization.substr('Bearer='.length) : null
    if (token === null) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    const loggedInUser = security.authenticatedUsers.get(token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    // Proving knowledge of the current password is mandatory, not just
    // checked-when-present: a missing/empty `current` must be rejected the
    // same way a wrong one is, otherwise a stolen or forged session token
    // alone is enough to take over the account.
    if (!currentPassword || security.hash(currentPassword) !== loggedInUser.data.password) {
      res.status(401).send(res.__('Current password is not correct.'))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }

      await user.update({ password: newPasswordInString })
      // Revoke every other session for this account now that the password
      // has changed, so a token obtained before the change (stolen, leaked,
      // or otherwise not the one used to perform this change) stops working
      // immediately instead of remaining valid for its full remaining
      // lifetime. The token that performed the change stays valid.
      security.authenticatedUsers.invalidateSessionsOf(user.id, token)
      res.json({ user })
    } catch (error) {
      next(error)
    }
  }
}
