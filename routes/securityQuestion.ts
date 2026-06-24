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
      // Issue: The endpoint returned the user's real security question for a registered email but an empty object {} for an unregistered one.
      // Risk: Account/user enumeration (CWE-204) — an attacker can confirm which emails are registered, enabling targeted password-guessing/phishing.
      // Fix: Always return the same { question } shape. For an unknown email, return a deterministic decoy question derived from the email so the response is consistent across repeated queries and indistinguishable from a registered email.
      let question
      if (answer != null) {
        question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
      } else {
        const questionCount = await SecurityQuestionModel.count()
        if (questionCount > 0) {
          const emailString = email?.toString() ?? ''
          let derivedOffset = 0
          for (let i = 0; i < emailString.length; i++) {
            derivedOffset = (derivedOffset + emailString.charCodeAt(i)) % questionCount
          }
          question = await SecurityQuestionModel.findOne({ offset: derivedOffset, order: [['id', 'ASC']] })
        } else {
          question = null
        }
      }
      res.json({ question })
    } catch (error) {
      next(error)
    }
  }
}
