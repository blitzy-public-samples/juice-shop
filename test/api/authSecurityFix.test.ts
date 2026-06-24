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

before(async () => {
  const result = await createTestApp()
  app = result.app
  domain = config.get<string>('application.domain')
  knownEmail = `authsecfix.known@${domain}`
  logoutEmail = `authsecfix.logout@${domain}`
  await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email: knownEmail, password: knownPassword })
  await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({ email: logoutEmail, password: logoutPassword })
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
