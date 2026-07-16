/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'

export function repeatNotification () {
  return ({ query }: Request, res: Response) => {
    let challengeName = ''
    try {
      challengeName = query.challenge ? decodeURIComponent(query.challenge as string) : ''
    } catch {
      res.status(400).json({ status: 'error', message: 'Invalid challenge name' })
      return
    }
    const challenge = challengeUtils.findChallengeByName(challengeName)

    if (challenge?.solved) {
      challengeUtils.sendNotification(challenge, true)
    }

    res.sendStatus(200)
  }
}
