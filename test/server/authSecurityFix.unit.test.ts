/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'
import * as security from '../../lib/insecurity'
import { login } from '../../routes/login'
import * as models from '../../models/index'
import type { UserModel } from '@juice-shop/models/user'

// Forged tokens reused verbatim from the project's JWT challenge fixtures (see test/server/verify.unit.test.ts):
//  1) an alg=none unsigned token, and
//  2) an HS256 token signed using the public RSA key (algorithm-confusion attack).
// The hardened verify() pins RS256 and MUST reject both.
const algNoneToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
const hs256ForgedToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgyMjIxNTc1fQ.ycFwtqh4ht4Pq9K5rhiPPY256F9YCTIecd4FHFuSEAg'

// A genuine RS256 token signed with the project's RSA key pair (verifiable against encryptionkeys/jwt.pub)
// whose `exp` (1600000000, Sep 2020) is in the past. It passes the RS256 header + signature checks, so it
// isolates the expiry guard: the hardened verify() MUST still reject it because it is expired.
const expiredRs256Token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImVtYWlsIjoiZXhwaXJlZC1yczI1NkBqdWljZS1zaC5vcCJ9LCJpYXQiOjE1OTk5OTAwMDAsImV4cCI6MTYwMDAwMDAwMH0.QB7--MuNcXpbyJ3OeG1Bp0v1z_mKV1XA_rgWPYJdoz0HJ1p2y86hRtbKG-tZQuYRLfQfIfb2_QIquQiy7fzEPJgNB-GTYStYa0gnzn0tUFUk-o1KrDe0LefHvQC7U_FBx3Qx7HXFWRer4L0pvgmlhgcE4FJWLyk2s6cH4izm6ew'

void describe('[Security Fix] Broken Authentication - lib/insecurity', () => {
  void describe('hashPassword / comparePassword (bcrypt, cost 12)', () => {
    void it('hashPassword returns a bcrypt hash with cost factor 12 (not MD5)', () => {
      const hashed = security.hashPassword('S3curePassw0rd!')
      assert.match(hashed, /^\$2[aby]\$12\$/)
      assert.equal(hashed.length, 60)
      assert.ok(!/^[a-f0-9]{32}$/i.test(hashed))
      assert.notEqual(hashed, security.hash('S3curePassw0rd!'))
    })

    void it('comparePassword returns true for the correct password and false otherwise', () => {
      const hashed = security.hashPassword('S3curePassw0rd!')
      assert.equal(security.comparePassword('S3curePassw0rd!', hashed), true)
      assert.equal(security.comparePassword('wrong-password', hashed), false)
    })
  })

  void describe('verify (RS256 pinned)', () => {
    void it('returns false for an alg=none (unsigned) token', () => {
      assert.equal(security.verify(algNoneToken), false)
    })

    void it('returns false for an HS256 token signed with the public RSA key', () => {
      assert.equal(security.verify(hs256ForgedToken), false)
    })

    void it('returns true for a genuine RS256 token issued by authorize()', () => {
      const token = security.authorize({ data: { email: 'rs256-test@juice-sh.op' } })
      assert.equal(security.verify(token), true)
    })

    void it('returns false for an empty/missing token', () => {
      assert.equal(security.verify(''), false)
    })

    void it('returns false for an expired RS256 token (valid signature, exp in the past)', () => {
      assert.equal(security.verify(expiredRs256Token), false)
    })
  })

  void describe('token denylist (invalidate / isTokenBlocked)', () => {
    void it('invalidate() denylists the token and removes it from authenticatedUsers', () => {
      const token = security.authorize({ data: { id: 90001, email: 'denylist-test@juice-sh.op' } })
      security.authenticatedUsers.put(token, { data: { id: 90001, email: 'denylist-test@juice-sh.op' } as unknown as UserModel })

      assert.ok(security.authenticatedUsers.get(token))
      assert.equal(security.isTokenBlocked(token), false)

      security.invalidate(token)

      assert.equal(security.isTokenBlocked(token), true)
      assert.equal(security.authenticatedUsers.get(token), undefined)
    })

    void it('verify() returns false for a denylisted (logged-out) token even though its signature and exp are valid', () => {
      const token = security.authorize({ data: { id: 90002, email: 'denylist-verify@juice-sh.op' } })
      // A freshly issued token verifies successfully...
      assert.equal(security.verify(token), true)
      // ...but once logged out it must be rejected at the verify() entry point used by direct callers.
      security.invalidate(token)
      assert.equal(security.verify(token), false)
    })
  })

  void describe('authorize (<= 1 hour token lifetime)', () => {
    void it('issues a token whose exp is at most one hour after iat', () => {
      const token = security.authorize({ data: { email: 'exp-test@juice-sh.op' } })
      const decoded = security.decode(token)
      assert.ok(decoded)
      assert.equal(typeof decoded.iat, 'number')
      assert.equal(typeof decoded.exp, 'number')
      const lifetimeSeconds = Number(decoded.exp) - Number(decoded.iat)
      assert.ok(lifetimeSeconds > 0)
      assert.ok(lifetimeSeconds <= 3600)
    })
  })

  void describe('isAuthorized (production middleware enforces RS256, expiry and denylist)', () => {
    // express-jwt@0.1.3 ignores the `algorithms` option, so isAuthorized() must reject forged/expired
    // tokens itself (via verify()) BEFORE delegating. These tests exercise that production middleware path.
    const invokeWith = (token: string) => {
      const req: any = { headers: { authorization: `Bearer ${token}` }, cookies: {} }
      let statusCode: number | undefined
      const res: any = {
        status (code: number) { statusCode = code; return this },
        json () { return this }
      }
      const next = mock.fn()
      security.isAuthorized()(req, res, next)
      return { statusCode: () => statusCode, next }
    }

    void it('rejects an alg=none forged token with HTTP 401 and does not call next()', () => {
      const { statusCode, next } = invokeWith(algNoneToken)
      assert.equal(statusCode(), 401)
      assert.equal(next.mock.calls.length, 0)
    })

    void it('rejects an HS256-with-public-key forged token with HTTP 401 and does not call next()', () => {
      const { statusCode, next } = invokeWith(hs256ForgedToken)
      assert.equal(statusCode(), 401)
      assert.equal(next.mock.calls.length, 0)
    })

    void it('rejects an expired RS256 token with HTTP 401 and does not call next()', () => {
      const { statusCode, next } = invokeWith(expiredRs256Token)
      assert.equal(statusCode(), 401)
      assert.equal(next.mock.calls.length, 0)
    })
  })

  void describe('updateAuthenticatedUsers (registry refuses forged tokens)', () => {
    // jsonwebtoken@0.4.0 ignores the `algorithms` option, so registry population must be gated by verify().
    void it('does not populate authenticatedUsers from an alg=none forged token', () => {
      const req: any = { cookies: { token: algNoneToken }, headers: {} }
      const cookie = mock.fn()
      const res: any = { cookie }
      const next = mock.fn()
      security.updateAuthenticatedUsers()(req, res, next)
      assert.equal(security.authenticatedUsers.get(algNoneToken), undefined)
      assert.equal(cookie.mock.calls.length, 0)
      assert.equal(next.mock.calls.length, 1)
    })

    void it('does not populate authenticatedUsers from an HS256 forged token', () => {
      const req: any = { cookies: { token: hs256ForgedToken }, headers: {} }
      const cookie = mock.fn()
      const res: any = { cookie }
      const next = mock.fn()
      security.updateAuthenticatedUsers()(req, res, next)
      assert.equal(security.authenticatedUsers.get(hs256ForgedToken), undefined)
      assert.equal(cookie.mock.calls.length, 0)
      assert.equal(next.mock.calls.length, 1)
    })

    void it('populates authenticatedUsers from a genuine RS256 token', () => {
      const token = security.authorize({ data: { id: 90003, email: 'update-genuine@juice-sh.op' } })
      const req: any = { cookies: { token }, headers: {} }
      const cookie = mock.fn()
      const res: any = { cookie }
      const next = mock.fn()
      security.updateAuthenticatedUsers()(req, res, next)
      assert.ok(security.authenticatedUsers.get(token))
      assert.equal(cookie.mock.calls.length, 1)
      assert.equal(next.mock.calls.length, 1)
    })
  })

  void describe('login (absent-user timing equalization pays the dummy bcrypt comparison)', () => {
    void it('returns a generic 401 for an unregistered email after performing the dummy bcrypt compare', async () => {
      // Force the "no user found" branch so the route falls back to the constant cost-12 DUMMY_PASSWORD_HASH.
      const queryMock = mock.method(models.sequelize, 'query', async () => null)
      const req: any = { body: { email: 'definitely-not-registered@juice-sh.op', password: 'whatever-wrong' } }
      let statusCode: number | undefined
      let sentMessage: string | undefined
      const res: any = {
        status (code: number) { statusCode = code; return this },
        send (message: string) { sentMessage = message; return this },
        json () { return this },
        __ (message: string) { return message }
      }
      const next = mock.fn()

      login()(req, res, next)
      // The handler runs its DB lookup + bcrypt comparison on the microtask queue; flush it before asserting.
      await new Promise((resolve) => setImmediate(resolve))

      const queryCalls = queryMock.mock.calls.length
      const nextCalls = next.mock.calls.length
      queryMock.mock.restore()

      // The absent-user path selects by email (one query) and reaches the generic 401 only AFTER the
      // unconditional security.comparePassword(..., DUMMY_PASSWORD_HASH) call, so timing is equalized.
      assert.equal(queryCalls, 1)
      assert.equal(statusCode, 401)
      assert.equal(sentMessage, 'Invalid email or password.')
      assert.equal(nextCalls, 0)
    })
  })
})
