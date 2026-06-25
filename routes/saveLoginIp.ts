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
        // [SECURITY FIX] Broken Authentication
        // Issue: The production client-side logout (Angular navbar/sidenav logout()) only calls GET /rest/saveLoginIp; it never calls the dedicated POST /rest/user/logout, so the JWT presented at logout was never invalidated server-side and stayed valid until its exp claim. In production this endpoint is invoked EXCLUSIVELY by that logout flow (its only callers are navbar.component.ts and sidenav.component.ts logout()), so a saveLoginIp request is effectively a logout event.
        // Risk: CWE-613 (insufficient session expiration / improper logout) — a token captured from a live session remained usable for authenticated API access after the user logged out through the UI, enabling session hijacking / account takeover for the remainder of the (1h) token lifetime.
        // Fix: After persisting the last-login IP, invalidate the presented bearer/cookie token (server-side denylist + authenticated-user registry eviction) so any subsequent request bearing it is rejected with 401. This makes the existing client-side logout actually "backed by the new server-side invalidation" (AAP §0.9.2) WITHOUT modifying the Angular frontend (AAP §0.11 no-frontend-modification directive). The dedicated POST /rest/user/logout endpoint remains for direct API callers. Uses optional chaining on cookies so non-logout/programmatic calls with no token are a safe no-op (invalidate() guards an empty token).
        const token = utils.jwtFrom(req) || req.cookies?.token
        security.invalidate(token)
        res.json(updatedUser)
      } catch (error) {
        next(error)
      }
    } else {
      res.sendStatus(401)
    }
  }
}
