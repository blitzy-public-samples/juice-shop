/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from '@juice-shop/models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import bcrypt from 'bcryptjs'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

// [SECURITY FIX] Broken Authentication
// Issue: The RSA private signing key was hardcoded inline in source (its public half is browsable at /encryptionkeys/jwt.pub), and the prior remediation kept that exact secret as an operative runtime fallback, so the app could still sign valid JWTs from a committed key with no environment configured.
// Risk: CWE-321/CWE-798 — a committed signing key lets anyone with source/repo access forge a token for any user (incl. admin) → full account takeover; keeping it as a fallback leaves the secret operative in production.
// Fix: Remove the committed private key entirely. Source the signing key ONLY from the environment (JWT_PRIVATE_KEY, normalizing literal \n) or a key file (JWT_PRIVATE_KEY_PATH / an uncommitted encryptionkeys/jwt.key). When none is configured the app FAILS CLOSED in production; outside production it generates a throwaway EPHEMERAL RSA key pair (never the original secret, regenerated each boot) so local/dev/test still boot. The verification public key is ALWAYS DERIVED from the active private key (crypto.createPublicKey), so any operator-supplied key works and signing/verification can never be configured with a mismatched pair (the committed jwt.pub is no longer assumed to match the signing key).
const loadKeyMaterial = (): { privateKey: string, publicKey: string } => {
  // Derive the verification public key directly from whatever private key is active, so signing (authorize)
  // and verification (verify/isAuthorized/updateAuthenticatedUsers) always use a matching pair regardless of
  // which key the operator provides — eliminating the mismatched private/public key deployment failure mode.
  const fromPrivateKey = (privateKeyPem: string) => ({
    privateKey: privateKeyPem,
    publicKey: crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }).toString()
  })
  // 1) Inline PEM supplied via the environment (production). Normalize literal "\n" sequences to real newlines.
  if (process.env.JWT_PRIVATE_KEY !== undefined && process.env.JWT_PRIVATE_KEY !== '') {
    return fromPrivateKey(process.env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n'))
  }
  // 2) Path to a PEM file on disk supplied via the environment.
  if (process.env.JWT_PRIVATE_KEY_PATH !== undefined && process.env.JWT_PRIVATE_KEY_PATH !== '') {
    return fromPrivateKey(fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH, 'utf8'))
  }
  // 3) Conventional local key file, if present (developer-supplied, NOT committed to the repository).
  if (fs.existsSync('encryptionkeys/jwt.key')) {
    return fromPrivateKey(fs.readFileSync('encryptionkeys/jwt.key', 'utf8'))
  }
  // 4) Production with no configured key: FAIL CLOSED rather than fall back to any embedded secret.
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT signing key is not configured. Set JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH (or provide an uncommitted encryptionkeys/jwt.key) before starting in production.')
  }
  // 5) Local/dev/test fallback: generate a throwaway EPHEMERAL RSA key pair (regenerated every boot; never the
  //    original committed secret). Both halves stay in-process so authorize()/verify() remain mutually consistent.
  const ephemeral = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  })
  console.warn('[insecurity] No JWT signing key configured (JWT_PRIVATE_KEY / JWT_PRIVATE_KEY_PATH / encryptionkeys/jwt.key); generated an EPHEMERAL development/test key pair. Tokens will not survive a restart — configure a key for any non-local use.')
  return { privateKey: ephemeral.privateKey, publicKey: ephemeral.publicKey }
}
const keyMaterial = loadKeyMaterial()
export const publicKey = keyMaterial.publicKey
const privateKey = keyMaterial.privateKey

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
  delete: (token: string) => void
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
// [SECURITY FIX] Broken Authentication
// Issue: The HMAC secret used to hash security answers was hardcoded inline in source and was kept as an operative `?? 'pa4qacea4VK9t9nGv7yZtwmj'` fallback, so the original committed secret stayed in effect whenever HMAC_SECRET was unset.
// Risk: CWE-798 — a known, source-embedded secret lets anyone forge/precompute security-answer HMACs; an always-on fallback leaves it operative in production.
// Fix: Source the secret from process.env.HMAC_SECRET. When it is unset, FAIL CLOSED everywhere except: NODE_ENV==='test' uses the prior literal as a non-production, test-only gated fixture (so deterministic test vectors hold), and other non-production runs use a throwaway random per-boot secret. The committed secret is therefore never operative in production/default runtime.
const resolveHmacSecret = (): string => {
  if (process.env.HMAC_SECRET !== undefined && process.env.HMAC_SECRET !== '') {
    return process.env.HMAC_SECRET
  }
  if (process.env.NODE_ENV === 'test') {
    // Test-only gated fixture (explicitly NOT used in production/default runtime).
    return 'pa4qacea4VK9t9nGv7yZtwmj'
  }
  if (process.env.NODE_ENV !== 'production') {
    // Local/dev: throwaway random secret (never the committed value); regenerated each boot.
    return crypto.randomBytes(32).toString('hex')
  }
  throw new Error('HMAC_SECRET is not configured. Set process.env.HMAC_SECRET before starting in production.')
}
const hmacSecret = resolveHmacSecret()
export const hmac = (data: string) => crypto.createHmac('sha256', hmacSecret).update(data).digest('hex')

// [SECURITY FIX] Broken Authentication
// Issue: Passwords were stored/compared with fast, unsalted MD5 (security.hash).
// Risk: CWE-327/CWE-916 — trivial offline cracking / rainbow tables → mass credential compromise.
// Fix: Provide bcrypt (cost factor 12) helpers for password hashing and constant-time comparison. The MD5 hash() above is retained ONLY for non-authentication uses (order IDs, email-display hashes).
export const hashPassword = (password: string) => bcrypt.hashSync(password, 12)
export const comparePassword = (password: string, passwordHash: string) => bcrypt.compareSync(password, passwordHash)

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

// [SECURITY FIX] Broken Authentication
// Issue: There was no server-side logout; tokens stayed valid until exp even after the user "logged out".
// Risk: CWE-613 — a stolen or forwarded token remained usable after logout.
// Fix: Maintain an in-memory token denylist (process-local; clears on restart) and reject denylisted tokens at every verification site.
const tokenDenylist = new Set<string>()
export const isTokenBlocked = (token: string) => Boolean(token) && tokenDenylist.has(utils.unquote(token))

// [SECURITY FIX] Broken Authentication
// Issue: The pinned express-jwt@0.1.3 IGNORES the `algorithms` option, so the middleware did not actually enforce RS256; attacker-controlled "alg" (alg=none, or HS256 signed with the public key), as well as denylisted (logged-out) and expired tokens, were still accepted on protected routes.
// Risk: CWE-347 (improper signature/algorithm verification) → token forgery & account takeover; CWE-613 → a logged-out or expired token stayed usable until its (previously unchecked) exp.
// Fix: Gate every request on the hardened verify() (which enforces RS256, signature, expiry and the denylist) and reject with HTTP 401 BEFORE delegating. Genuine RS256 tokens still flow through express-jwt so req.user is populated exactly as before.
export const isAuthorized = () => {
  const jwtMiddleware = expressJwt(({ secret: publicKey, algorithms: ['RS256'] }) as any)
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req) || req.cookies?.token
    if (token && !verify(token)) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    jwtMiddleware(req, res, next)
  }
}
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
// [SECURITY FIX] Broken Authentication
// Issue: Access tokens carried no enforceable short lifetime (the original `expiresIn: '6h'` was, in addition, silently ignored by the pinned jsonwebtoken@0.4.0, leaving tokens effectively non-expiring).
// Risk: CWE-613 — a stolen token remained usable indefinitely / for a long window.
// Fix: Emit an explicit exp claim of 1 hour. NOTE: jsonwebtoken@0.4.0 does NOT honor the `expiresIn` string option (it sets no exp), so the 0.4.0-native `expiresInMinutes: 60` is used to actually produce exp = iat + 3600; the options are cast `as any` because @types/jsonwebtoken omits this legacy field. Algorithm RS256 retained; signing key now sourced from the environment.
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresInMinutes: 60, algorithm: 'RS256' } as any)
// [SECURITY FIX] Broken Authentication
// Issue: verify() (1) trusted the token's self-declared algorithm (jws.verify with no pinned algorithm), so alg=none and HS256-signed-with-the-public-key forgeries passed; (2) checked only the signature and never the `exp` claim, so expired RS256 tokens still returned true; (3) never consulted the logout denylist, so a logged-out token still verified for direct callers (currentUser, deluxe, 2fa, role helpers).
// Risk: CWE-347 (algorithm/signature confusion → token forgery & account takeover); CWE-613 (expired or logged-out tokens remained usable until exp). verify() is the single hardened verifier reused by isAuthorized() and updateAuthenticatedUsers().
// Fix: Reject, in order, (a) denylisted/logged-out tokens, (b) any token whose header alg is not RS256, (c) tokens that fail RS256 signature verification against the public key, and (d) tokens whose `exp` claim is missing or already in the past.
export const verify = (token: string) => {
  if (!token) return false
  if (isTokenBlocked(token)) return false
  try {
    const decoded = jws.decode(token)
    if (decoded?.header?.alg !== 'RS256') return false
    if (!(jws.verify as ((token: string, secret: string) => boolean))(token, publicKey)) return false
    const exp = (decoded?.payload as { exp?: number } | undefined)?.exp
    if (typeof exp !== 'number' || exp <= Math.floor(Date.now() / 1000)) return false
    return true
  } catch {
    return false
  }
}
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  // [SECURITY FIX] Broken Authentication
  // Issue: get() (and from(), which delegates to it) returned a cached user straight from the registry without re-checking the token, so a token cached by updateAuthenticatedUsers() before it expired — or one later denylisted via logout — was still accepted by registry-backed routes even though verify() returns false.
  // Risk: CWE-613 — expired or logged-out tokens remained usable through cached registry reads, creating a split-brain auth model where verify() rejects a token while registry consumers accept it.
  // Fix: Re-validate the token through the hardened verify() (RS256 + signature + expiry + denylist) on every read and evict the stale entry when it fails, so registry reads enforce the same expiry/denylist semantics as verify().
  get: function (token?: string) {
    if (!token) return undefined
    const user = this.tokenMap[utils.unquote(token)]
    if (user === undefined) return undefined
    if (!verify(token)) {
      this.delete(token)
      return undefined
    }
    return user
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  },
  // [SECURITY FIX] Broken Authentication
  // Issue: The authenticated-user registry exposed put/get/tokenOf/from/updateFrom but had NO eviction method, so server-side logout could not drop a session and stale/expired entries lingered indefinitely.
  // Risk: CWE-613 — without eviction a logged-out or expired token's cached user remained in the registry and could keep being served to registry-backed routes after it should have been invalid.
  // Fix: Add delete() so invalidate()/logout and the hardened get() re-validation path can evict an entry. Because put() stores under the raw token while get() reads the unquoted token, remove BOTH forms defensively and clear the idMap entry.
  delete: function (token: string) {
    const unquoted = utils.unquote(token)
    const user = this.tokenMap[unquoted] ?? this.tokenMap[token]
    if (user?.data?.id !== undefined) {
      delete this.idMap[user.data.id]
    }
    delete this.tokenMap[unquoted]
    delete this.tokenMap[token]
  }
}

// [SECURITY FIX] Broken Authentication
// Issue: No server-side logout existed; tokens stayed valid until exp.
// Risk: CWE-613 — a stolen/forwarded token remained usable after "logout".
// Fix: Denylist the token and drop it from the authenticated-user registry so subsequent requests are rejected with 401.
export const invalidate = (token: string) => {
  if (!token) return
  const unquoted = utils.unquote(token)
  tokenDenylist.add(unquoted)
  authenticatedUsers.delete(unquoted)
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

// [SECURITY FIX] Broken Authentication
// Issue: appendUserId() read the user id straight from authenticatedUsers.tokenMap, bypassing the hardened get(), so an expired or logged-out token still cached in the registry was accepted and its UserId attached to the request.
// Risk: CWE-613 — a stale/expired/denylisted token could still authorize basket/order writes via this middleware even though verify() rejects it everywhere else.
// Fix: Resolve the user through authenticatedUsers.get(), which re-validates the token via verify() (RS256 + signature + expiry + denylist) and evicts stale entries; an invalid token yields undefined, so the existing catch returns HTTP 401 exactly as before.
export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = authenticatedUsers.get(utils.jwtFrom(req))
      if (user === undefined) {
        throw new Error('Unauthenticated request')
      }
      req.body.UserId = user.data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

// [SECURITY FIX] Broken Authentication
// Issue: The authenticated-user registry was populated via jwt.verify, but the pinned jsonwebtoken@0.4.0 IGNORES the `algorithms` option, so forged alg=none / HS256-with-public-key tokens (and denylisted or expired tokens) were decoded and cached as authenticated users — letting the app treat attacker-controlled payloads as logged-in users.
// Risk: CWE-347 token forgery via algorithm confusion; CWE-613 logged-out/expired tokens remained usable.
// Fix: Gate registry population on the hardened verify() (RS256 + signature + expiry + denylist). jwt.verify is now only ever reached with an already-verified RS256 token, which it merely decodes for caching.
export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token && verify(token) && authenticatedUsers.get(token) === undefined) {
    jwt.verify(token, publicKey, { algorithms: ['RS256'] } as any, (err: Error | null, decoded: any) => {
      if (err === null && decoded?.data !== undefined) {
        authenticatedUsers.put(token, decoded)
        res.cookie('token', token)
      }
    })
  }
  next()
}
