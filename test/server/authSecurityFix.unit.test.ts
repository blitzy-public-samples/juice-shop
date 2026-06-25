/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'
import * as security from '../../lib/insecurity'
import { login } from '../../routes/login'
import { securityQuestion } from '../../routes/securityQuestion'
import { SecurityQuestionModel } from '../../models/securityQuestion'
import { SecurityAnswerModel } from '../../models/securityAnswer'
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

  void describe('authenticatedUsers.get()/from() re-validate cached tokens (no stale acceptance)', () => {
    // Regression coverage for the registry stale-cache defect: once a token is cached by
    // updateAuthenticatedUsers(), the read paths (get / from / appendUserId) MUST re-validate it via the
    // hardened verify() and evict it when it no longer holds, so an expired or logged-out token can never be
    // served from cache after verify() would reject it. put() performs no verification, so it faithfully
    // models a registry entry that was cached while valid and has since gone stale.
    void it('get() refuses and evicts a cached token whose signature/exp no longer verifies (expired)', () => {
      security.authenticatedUsers.put(expiredRs256Token, { data: { id: 90010, email: 'stale-expired@juice-sh.op' } as unknown as UserModel })
      // A registry read must re-validate and refuse the stale (expired) entry...
      assert.equal(security.authenticatedUsers.get(expiredRs256Token), undefined)
      // ...and must have evicted it so it cannot be served on a subsequent read.
      assert.equal(security.authenticatedUsers.tokenMap[expiredRs256Token], undefined)
    })

    void it('get() refuses and evicts a denylisted (logged-out) token still lingering in the registry', () => {
      const token = security.authorize({ data: { id: 90011, email: 'stale-denylisted@juice-sh.op' } })
      // The genuine token verifies before logout...
      assert.equal(security.verify(token), true)
      // ...then logout denylists (and drops) it; we re-insert to simulate a stale cached entry surviving logout.
      security.invalidate(token)
      security.authenticatedUsers.put(token, { data: { id: 90011, email: 'stale-denylisted@juice-sh.op' } as unknown as UserModel })
      assert.equal(security.verify(token), false)
      assert.equal(security.authenticatedUsers.get(token), undefined)
      assert.equal(security.authenticatedUsers.tokenMap[token], undefined)
    })

    void it('from() delegates to the re-validating get() and rejects a stale cached token from the request', () => {
      security.authenticatedUsers.put(expiredRs256Token, { data: { id: 90012, email: 'stale-from@juice-sh.op' } as unknown as UserModel })
      const req: any = { headers: { authorization: `Bearer ${expiredRs256Token}` } }
      assert.equal(security.authenticatedUsers.from(req), undefined)
      assert.equal(security.authenticatedUsers.tokenMap[expiredRs256Token], undefined)
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

    // Regression for QA Issue #2 (SC5 edge case): jsonwebtoken@0.4.0 derives the token solely from the
    // payload + a second-granularity iat, so two authorize() calls with an identical payload within the same
    // second used to produce a BYTE-IDENTICAL token. With the whole-token logout denylist this meant an
    // immediate re-login after logout returned the just-denylisted token. authorize() now adds a unique jti
    // nonce, so every issued token is distinct (and still a valid RS256 token) regardless of timing/payload.
    void it('issues a UNIQUE token on each call for an identical payload (jti nonce)', () => {
      const payload = { data: { id: 90020, email: 'jti-unique@juice-sh.op' } }
      const tokenA = security.authorize(payload)
      const tokenB = security.authorize(payload)
      assert.notEqual(tokenA, tokenB)
      // Both must still be genuine, verifiable RS256 tokens...
      assert.equal(security.verify(tokenA), true)
      assert.equal(security.verify(tokenB), true)
      // ...each carries a distinct jti, and the business payload (data) is preserved unchanged.
      const decodedA: any = security.decode(tokenA)
      const decodedB: any = security.decode(tokenB)
      assert.equal(typeof decodedA.jti, 'string')
      assert.equal(typeof decodedB.jti, 'string')
      assert.notEqual(decodedA.jti, decodedB.jti)
      assert.equal(decodedA.data.email, 'jti-unique@juice-sh.op')
      // The caller's payload object must NOT be mutated by the nonce injection (it is stored in authenticatedUsers).
      assert.equal(Object.prototype.hasOwnProperty.call(payload, 'jti'), false)
    })

    // Regression for QA Issue #2: model the exact login -> logout -> immediate relogin sequence at the helper
    // level. The first token is denylisted by invalidate(); a re-issued token for the SAME payload must NOT be
    // denylisted (it is a different token thanks to the jti nonce) and must verify successfully.
    void it('re-issued token after invalidate() of an identical-payload token is NOT denylisted', () => {
      const payload = { data: { id: 90021, email: 'jti-relogin@juice-sh.op' } }
      const first = security.authorize(payload)
      assert.equal(security.verify(first), true)
      security.invalidate(first) // logout
      assert.equal(security.verify(first), false)
      const second = security.authorize(payload) // immediate relogin, same payload
      assert.notEqual(first, second)
      assert.equal(security.isTokenBlocked(second), false)
      assert.equal(security.verify(second), true)
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

void describe('[Security Fix] Broken Authentication - securityQuestion (no enumeration via DB access pattern)', () => {
  // Finding #5: the response shape was already uniform, but the registered and unregistered branches performed
  // a different number/type of database lookups, leaving a query-count/latency enumeration oracle. The fix makes
  // BOTH branches run count() + findByPk() exactly once. These tests mock the models and assert the query
  // pattern (which methods, how many times) is identical for a known vs an unknown email.
  const invoke = async (email: string, answerValue: unknown) => {
    const answerFindOne = mock.method(SecurityAnswerModel, 'findOne', async () => answerValue)
    const questionCount = mock.method(SecurityQuestionModel, 'count', async () => 5)
    const questionFindByPk = mock.method(SecurityQuestionModel, 'findByPk', async (id: number) => ({ id, question: `Question ${id}` }))
    const questionFindOne = mock.method(SecurityQuestionModel, 'findOne', async () => ({ id: 1, question: 'Question 1' }))
    let body: { question?: unknown } | undefined
    const req: any = { query: { email } }
    const res: any = { json (payload: { question?: unknown }) { body = payload; return this } }
    const next = mock.fn()

    await securityQuestion()(req, res, next)

    const counts = {
      answerFindOne: answerFindOne.mock.calls.length,
      questionCount: questionCount.mock.calls.length,
      questionFindByPk: questionFindByPk.mock.calls.length,
      questionFindOne: questionFindOne.mock.calls.length,
      next: next.mock.calls.length
    }
    answerFindOne.mock.restore()
    questionCount.mock.restore()
    questionFindByPk.mock.restore()
    questionFindOne.mock.restore()
    return { body, counts }
  }

  void it('uses an identical query pattern and { question } response shape for known and unknown emails', async () => {
    const known = await invoke('known@juice-sh.op', { SecurityQuestionId: 3 })
    const unknown = await invoke('unknown@juice-sh.op', null)

    // The query pattern (which model methods, and how many times) must be identical so that neither the query
    // count nor the resulting latency can reveal whether the email is registered.
    assert.deepEqual(known.counts, unknown.counts)
    // Both branches go through count() + findByPk() exactly once and never the asymmetric findOne() path.
    assert.equal(known.counts.questionCount, 1)
    assert.equal(known.counts.questionFindByPk, 1)
    assert.equal(known.counts.questionFindOne, 0)
    // Both responses carry the same { question } shape with a real question object.
    assert.ok(Object.prototype.hasOwnProperty.call(known.body, 'question'))
    assert.ok(Object.prototype.hasOwnProperty.call(unknown.body, 'question'))
    assert.equal(typeof (known.body as { question: { question: string } }).question.question, 'string')
    assert.equal(typeof (unknown.body as { question: { question: string } }).question.question, 'string')
  })

  void it('derives a deterministic decoy question for the same unknown email', async () => {
    const first = await invoke('stable.unknown@juice-sh.op', null)
    const second = await invoke('stable.unknown@juice-sh.op', null)
    assert.deepEqual(first.body, second.body)
  })
})
