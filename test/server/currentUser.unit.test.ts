/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { retrieveLoggedInUser } from '../../routes/currentUser'
import { authenticatedUsers, authorize } from '../../lib/insecurity'
import type { UserModel } from '@juice-shop/models/user'

void describe('currentUser', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = { cookies: {}, query: {} }
    res = { json: mock.fn() }
  })

  void it('should return neither ID nor email if no cookie was present in the request headers', () => {
    req.cookies.token = ''

    retrieveLoggedInUser()(req, res)

    assert.equal(res.json.mock.calls.length, 1)
    assert.deepEqual(res.json.mock.calls[0].arguments[0], { user: { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined } })
  })

  void it('should return ID and email of user belonging to cookie from the request', () => {
    // Signed here (rather than hardcoded) since the session-signing key is
    // now generated per-process instead of a fixed literal (TC-DCACAB28) --
    // a token pre-signed with any other key would no longer verify.
    const userData = { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' }
    const token = authorize({ data: userData })
    req.cookies.token = token
    req.query.callback = undefined
    authenticatedUsers.put(token, { data: userData as unknown as UserModel })
    retrieveLoggedInUser()(req, res)

    assert.equal(res.json.mock.calls.length, 1)
    assert.deepEqual(res.json.mock.calls[0].arguments[0], { user: userData })
  })

  void it('should never return sensitive session fields (password, totpSecret, role, deluxeToken) even when explicitly requested via the fields query parameter', () => {
    // Signed here (rather than hardcoded) since the session-signing key is
    // now generated per-process instead of a fixed literal (TC-DCACAB28) --
    // a token pre-signed with any other key would no longer verify.
    const token = authorize({ data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: 'default.svg' } })
    req.cookies.token = token
    req.query.fields = 'password,totpSecret,role,deluxeToken,lastLoginIp,isActive'
    authenticatedUsers.put(
      token,
      {
        data: {
          id: 1,
          email: 'admin@juice-sh.op',
          password: '0192023a7bbd73250516f069df18b500',
          totpSecret: 'SUPERSECRETTOTPSEED',
          role: 'admin',
          deluxeToken: 'topSecretDeluxeToken',
          lastLoginIp: '0.0.0.0',
          profileImage: '/assets/public/images/uploads/default.svg',
          isActive: true
        } as unknown as UserModel
      }
    )

    retrieveLoggedInUser()(req, res)

    assert.equal(res.json.mock.calls.length, 1)
    const responseUser = res.json.mock.calls[0].arguments[0].user
    assert.equal(responseUser.password, undefined, 'password must never be returned, even when named in fields=')
    assert.equal(responseUser.totpSecret, undefined, 'totpSecret must never be returned, even when named in fields=')
    assert.equal(responseUser.role, undefined, 'role must never be returned, even when named in fields=')
    assert.equal(responseUser.deluxeToken, undefined, 'deluxeToken must never be returned, even when named in fields=')
    assert.equal(responseUser.isActive, undefined, 'isActive must never be returned, even when named in fields=')
    // The allowlisted fields that were also requested should still come through.
    assert.equal(responseUser.lastLoginIp, '0.0.0.0')
  })

  void it('should return only the requested fields that are part of the safe allowlist', () => {
    // Signed here (rather than hardcoded) since the session-signing key is
    // now generated per-process instead of a fixed literal (TC-DCACAB28) --
    // a token pre-signed with any other key would no longer verify.
    const token = authorize({ data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: 'default.svg' } })
    req.cookies.token = token
    req.query.fields = 'email,profileImage'
    authenticatedUsers.put(
      token,
      { data: { id: 1, email: 'admin@juice-sh.op', lastLoginIp: '0.0.0.0', profileImage: '/assets/public/images/uploads/default.svg' } as unknown as UserModel }
    )

    retrieveLoggedInUser()(req, res)

    assert.equal(res.json.mock.calls.length, 1)
    assert.deepEqual(res.json.mock.calls[0].arguments[0], { user: { email: 'admin@juice-sh.op', profileImage: '/assets/public/images/uploads/default.svg' } })
  })
})
