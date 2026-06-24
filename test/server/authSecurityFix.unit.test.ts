/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as security from '../../lib/insecurity'
import type { UserModel } from '@juice-shop/models/user'

// Forged tokens reused verbatim from the project's JWT challenge fixtures (see test/server/verify.unit.test.ts):
//  1) an alg=none unsigned token, and
//  2) an HS256 token signed using the public RSA key (algorithm-confusion attack).
// The hardened verify() pins RS256 and MUST reject both.
const algNoneToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
const hs256ForgedToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgyMjIxNTc1fQ.ycFwtqh4ht4Pq9K5rhiPPY256F9YCTIecd4FHFuSEAg'

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
})
