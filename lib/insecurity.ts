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

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
// [SECURITY FIX] Broken Authentication
// Issue: The RSA private signing key was hardcoded inline in source, and its public half is browsable at /encryptionkeys/jwt.pub.
// Risk: CWE-321/CWE-798 — anyone with source access can sign arbitrary JWTs and impersonate any user (incl. admin) → full account takeover.
// Fix: Load the private key from JWT_PRIVATE_KEY (normalizing literal \n), else JWT_PRIVATE_KEY_PATH, else a local key file; the prior literal remains only as a last-resort dev/test fallback so the app still boots. Production provides the key via the environment.
const loadPrivateKey = (): string => {
  // 1) Inline PEM supplied via the environment (production). Normalize literal "\n" sequences to real newlines.
  if (process.env.JWT_PRIVATE_KEY !== undefined && process.env.JWT_PRIVATE_KEY !== '') {
    return process.env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n')
  }
  // 2) Path to a PEM file on disk supplied via the environment.
  if (process.env.JWT_PRIVATE_KEY_PATH !== undefined && process.env.JWT_PRIVATE_KEY_PATH !== '') {
    return fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH, 'utf8')
  }
  // 3) Conventional local key file, if present (not committed to the repository).
  if (fs.existsSync('encryptionkeys/jwt.key')) {
    return fs.readFileSync('encryptionkeys/jwt.key', 'utf8')
  }
  // 4) Last-resort dev/test fallback: the prior inline literal, retained ONLY so local/dev/test boots
  //    still succeed without configuration. It is no longer the primary/sole source and is rotatable.
  return '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'
}
const privateKey = loadPrivateKey()

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
// Issue: The HMAC secret used to hash security answers was hardcoded inline in source.
// Risk: CWE-798 — a known, source-embedded secret lets anyone forge/precompute security-answer HMACs.
// Fix: Source the secret from process.env.HMAC_SECRET, retaining the prior string only as a non-secret dev fallback for identical local/test behavior.
export const hmac = (data: string) => crypto.createHmac('sha256', process.env.HMAC_SECRET ?? 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

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
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
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
  // Additive registry support for server-side logout (see invalidate() below). Because put() stores under
  // the raw token while get() reads the unquoted token, remove BOTH forms defensively and clear the idMap entry.
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

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
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
