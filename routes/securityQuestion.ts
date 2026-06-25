/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'

export function securityQuestion () {
  return async ({ query }: Request, res: Response, next: NextFunction) => {
    const email = query.email
    try {
      const answer = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email: email?.toString() }
        }]
      })
      // [SECURITY FIX] Broken Authentication
      // Issue: The endpoint returned the user's real security question for a registered email but an empty object {} for an unregistered one. A prior fix unified the response shape, but the two branches still performed a DIFFERENT number/type of database lookups (registered: a single findByPk; unregistered: count + findOne), leaving a query-count/latency side channel that still revealed whether an email was registered.
      // Risk: Account/user enumeration (CWE-204) — an attacker can confirm which emails are registered via the response body OR via response-time/query-count differences, enabling targeted password-guessing/phishing.
      // Fix: Always return the same { question } shape AND perform an IDENTICAL database access pattern for every input — unconditionally count the questions, then resolve exactly one question via findByPk (the same query type for both branches; the count() is a deliberate dummy-equivalent lookup so the registered path does the same work as the unregistered one). For a registered email this is the user's real question; for an unregistered one it is a deterministic decoy id derived from the email (stable across repeated probes; seeded question ids are contiguous 1..N so the id is always valid). Registered and unregistered emails are therefore indistinguishable by body, status, query count, or timing.
      const questionCount = await SecurityQuestionModel.count()
      let questionId: number | null = null
      if (questionCount > 0) {
        if (answer != null) {
          questionId = answer.SecurityQuestionId
        } else {
          const emailString = email?.toString() ?? ''
          let derivedOffset = 0
          for (let i = 0; i < emailString.length; i++) {
            derivedOffset = (derivedOffset + emailString.charCodeAt(i)) % questionCount
          }
          questionId = derivedOffset + 1
        }
      }
      const question = questionId != null ? await SecurityQuestionModel.findByPk(questionId) : null
      res.json({ question })
    } catch (error) {
      next(error)
    }
  }
}
