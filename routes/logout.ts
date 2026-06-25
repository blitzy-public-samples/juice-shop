/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// [SECURITY FIX] Broken Authentication
// Issue: There was no server-side logout; a JWT stayed valid until its exp claim even after the user "logged out" (logout was performed only client-side).
// Risk: CWE-613 (insufficient session expiration) — a stolen or forwarded token remained usable after logout, enabling session hijacking / account takeover.
// Fix: Invalidate the presented token on logout — add it to the server-side denylist and remove it from the authenticated-user registry — so any subsequent request bearing it is rejected with 401 by isAuthorized().
export function logout () {
  return (req: Request, res: Response) => {
    const token = utils.jwtFrom(req) || req.cookies.token
    security.invalidate(token)
    res.status(200).json({ status: 'success' })
  }
}
