/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'

let app: Express
let domain: string
let knownEmail: string
let logoutEmail: string
const knownPassword = 'Sup3rStr0ngPass1'
const logoutPassword = 'An0therStr0ngPass1'
const jsonHeader = { 'content-type': 'application/json' }

// [Security Fix] Broken Authentication — SC1 forged/expired JWT fixtures (reused verbatim from
// test/server/authSecurityFix.unit.test.ts). The hardened verify() pins RS256, so each of these MUST be
// rejected with HTTP 401 when presented to a protected route at the API layer:
//  - algNoneToken: an unsigned alg=none token (exp far in the future) — rejected because alg !== 'RS256'.
//  - hs256ForgedToken: an HS256 token signed with the PUBLIC RSA key (algorithm-confusion) — rejected because alg !== 'RS256'.
//  - expiredRs256Token: a genuine RS256 token (valid signature against encryptionkeys/jwt.pub) whose exp is in the past — rejected for expiry.
const algNoneToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.'
const hs256ForgedToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgyMjIxNTc1fQ.ycFwtqh4ht4Pq9K5rhiPPY256F9YCTIecd4FHFuSEAg'
const expiredRs256Token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImVtYWlsIjoiZXhwaXJlZC1yczI1NkBqdWljZS1zaC5vcCJ9LCJpYXQiOjE1OTk5OTAwMDAsImV4cCI6MTYwMDAwMDAwMH0.QB7--MuNcXpbyJ3OeG1Bp0v1z_mKV1XA_rgWPYJdoz0HJ1p2y86hRtbKG-tZQuYRLfQfIfb2_QIquQiy7fzEPJgNB-GTYStYa0gnzn0tUFUk-o1KrDe0LefHvQC7U_FBx3Qx7HXFWRer4L0pvgmlhgcE4FJWLyk2s6cH4izm6ew'

before(async () => {
  const result = await createTestApp()
  app = result.app
  domain = config.get<string>('application.domain')
  knownEmail = `authsecfix.known@${domain}`
  logoutEmail = `authsecfix.logout@${domain}`
  // Assert both seed registrations succeed (HTTP 201) before the suites run, so any setup breakage
  // surfaces here with an actionable diagnostic instead of as confusing downstream login failures.
  const knownRegistration = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email: knownEmail, password: knownPassword })
  assert.equal(knownRegistration.status, 201)
  const logoutRegistration = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email: logoutEmail, password: logoutPassword })
  assert.equal(logoutRegistration.status, 201)
}, { timeout: 60000 })

void describe('[Security Fix] Broken Authentication - login (hashing + enumeration)', () => {
  void it('accepts correct credentials and returns a JWT', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: knownEmail, password: knownPassword })

    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('rejects a wrong password with 401 and the generic message', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: knownEmail, password: 'definitely-not-the-password' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Invalid email or password'))
  })

  void it('rejects an unknown email with the SAME 401 response (no user enumeration)', async () => {
    const wrongPasswordRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: knownEmail, password: 'definitely-not-the-password' })

    const unknownEmailRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: `authsecfix.nobody@${domain}`, password: 'definitely-not-the-password' })

    assert.equal(unknownEmailRes.status, 401)
    assert.equal(unknownEmailRes.status, wrongPasswordRes.status)
    assert.equal(unknownEmailRes.text, wrongPasswordRes.text)
  })
})

void describe('[Security Fix] Broken Authentication - security question (no enumeration)', () => {
  void it('returns the same { question } shape for a known and an unknown email', async () => {
    const knownRes = await request(app)
      .get(`/rest/user/security-question?email=jim@${domain}`)
    const unknownRes = await request(app)
      .get('/rest/user/security-question?email=authsecfix.unknown@unknown-us.er')

    assert.equal(knownRes.status, 200)
    assert.equal(unknownRes.status, 200)

    assert.ok(knownRes.body.question)
    assert.equal(typeof knownRes.body.question.question, 'string')

    assert.ok(unknownRes.body.question)
    assert.equal(typeof unknownRes.body.question.question, 'string')
  })

  void it('returns a deterministic decoy question for the same unknown email', async () => {
    const first = await request(app)
      .get('/rest/user/security-question?email=authsecfix.stable@unknown-us.er')
    const second = await request(app)
      .get('/rest/user/security-question?email=authsecfix.stable@unknown-us.er')

    assert.equal(first.status, 200)
    assert.equal(second.status, 200)
    assert.deepEqual(first.body, second.body)
  })
})

void describe('[Security Fix] Broken Authentication - server-side logout (token invalidation)', () => {
  void it('rejects a token reused after logout with 401', async () => {
    const loginRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: logoutEmail, password: logoutPassword })
    assert.equal(loginRes.status, 200)
    const token = loginRes.body.authentication.token
    assert.equal(typeof token, 'string')

    const authHeader = { Authorization: `Bearer ${token}` }

    const beforeLogout = await request(app).get('/api/Users').set(authHeader)
    assert.equal(beforeLogout.status, 200)

    const logoutRes = await request(app).post('/rest/user/logout').set(authHeader)
    assert.equal(logoutRes.status, 200)

    const afterLogout = await request(app).get('/api/Users').set(authHeader)
    assert.equal(afterLogout.status, 401)
  })
})

void describe('[Security Fix] Broken Authentication - change password requires current password', () => {
  void it('rejects a password change that omits the current password with 401', async () => {
    const loginRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: knownEmail, password: knownPassword })
    assert.equal(loginRes.status, 200)
    const token = loginRes.body.authentication.token

    const res = await request(app)
      .get('/rest/user/change-password?new=BrandNewPass123&repeat=BrandNewPass123')
      .set({ Authorization: `Bearer ${token}` })

    assert.equal(res.status, 401)
  })
})

void describe('[Security Fix] Broken Authentication - JWT rejection at the API layer (SC1)', () => {
  // GET /api/Users is gated by security.isAuthorized() (server.ts), so presenting a forged or expired
  // token MUST be rejected with HTTP 401 and MUST NOT return the user collection (no successful access).
  const protectedRoute = '/api/Users'

  void it('rejects an alg=none (unsigned) forged token with 401 on a protected route', async () => {
    const res = await request(app)
      .get(protectedRoute)
      .set({ Authorization: `Bearer ${algNoneToken}` })

    assert.equal(res.status, 401)
    assert.equal(Array.isArray(res.body.data), false)
  })

  void it('rejects an HS256 token signed with the public RSA key (algorithm confusion) with 401', async () => {
    const res = await request(app)
      .get(protectedRoute)
      .set({ Authorization: `Bearer ${hs256ForgedToken}` })

    assert.equal(res.status, 401)
    assert.equal(Array.isArray(res.body.data), false)
  })

  void it('rejects an expired RS256 token (valid signature, exp in the past) with 401', async () => {
    const res = await request(app)
      .get(protectedRoute)
      .set({ Authorization: `Bearer ${expiredRs256Token}` })

    assert.equal(res.status, 401)
    assert.equal(Array.isArray(res.body.data), false)
  })

  void it('issues fresh login tokens whose lifetime (exp - iat) does not exceed one hour', async () => {
    const loginRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: knownEmail, password: knownPassword })
    assert.equal(loginRes.status, 200)

    const token = loginRes.body.authentication.token
    assert.equal(typeof token, 'string')

    // Decode the JWT payload (middle segment) at the API layer and verify the issued lifetime is <= 1 hour.
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) as { iat: number, exp: number }
    assert.equal(typeof payload.iat, 'number')
    assert.equal(typeof payload.exp, 'number')

    const lifetimeSeconds = payload.exp - payload.iat
    assert.ok(lifetimeSeconds > 0)
    assert.ok(lifetimeSeconds <= 3600)
  })
})
