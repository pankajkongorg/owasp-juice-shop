/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import pug from 'pug'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const code = username?.substring(2, username.length - 1)
      try {
        if (!code) {
          throw new Error('Username is null')
        }
        username = eval(code) // eslint-disable-line no-eval
      } catch (err) {
        username = '\\' + username
      }
    } else {
      username = '\\' + username
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, username)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    const fn = pug.compile(template)
    const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval' https://code.getmdl.io http://ajax.googleapis.com`

    challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
      return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
    })

    res.set({
      'Content-Security-Policy': CSP
    })

    res.send(fn(user))
  }
}

// Insecure Direct Object Reference (IDOR) vulnerability for testing detection tools
export function getUserProfileById() {
  return async (req: Request, res: Response, next: NextFunction) => {
    // VULNERABLE: IDOR vulnerability - users can access other users' profiles by changing the ID
    
    const requestedUserId = req.params.userId // User input from URL parameter
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }
    
    // CRITICAL: No authorization check - any authenticated user can access any profile
    // Missing check: if (loggedInUser.data.id !== parseInt(requestedUserId) && loggedInUser.data.role !== 'admin')
    
    let targetUser: UserModel | null
    try {
      // VULNERABLE: Direct access to any user by ID without permission check
      targetUser = await UserModel.findByPk(requestedUserId)
    } catch (error) {
      next(error)
      return
    }
    
    if (!targetUser) {
      res.status(404).json({ error: 'User not found' })
      return
    }
    
    // VULNERABLE: Exposing sensitive user data without authorization
    res.json({
      status: 'success',
      data: {
        id: targetUser.id,
        username: targetUser.username,
        email: targetUser.email, // Sensitive information exposed
        role: targetUser.role,
        profileImage: targetUser.profileImage,
        lastLoginIp: targetUser.lastLoginIp, // Sensitive information exposed
        isActive: targetUser.isActive,
        createdAt: targetUser.createdAt
      }
    })
  }
}

// Another IDOR vulnerability - user data export without proper authorization
export function exportUserData() {
  return async (req: Request, res: Response, next: NextFunction) => {
    const targetUserId = req.body.userId || req.query.userId // User input from request
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    
    if (!loggedInUser) {
      next(new Error('Authentication required'))
      return
    }
    
    // VULNERABLE: No authorization check - users can export any user's data
    // Missing check: if (loggedInUser.data.id !== parseInt(targetUserId) && loggedInUser.data.role !== 'admin')
    
    try {
      const targetUser = await UserModel.findByPk(targetUserId)
      
      if (!targetUser) {
        res.status(404).json({ error: 'User not found' })
        return
      }
      
      // VULNERABLE: Exposing all user data including sensitive information
      const userData = {
        id: targetUser.id,
        username: targetUser.username,
        email: targetUser.email,
        role: targetUser.role,
        profileImage: targetUser.profileImage,
        lastLoginIp: targetUser.lastLoginIp,
        isActive: targetUser.isActive,
        createdAt: targetUser.createdAt,
        updatedAt: targetUser.updatedAt,
        // Even more sensitive data that should be protected
        deluxeToken: targetUser.deluxeToken,
        totpSecret: targetUser.totpSecret
      }
      
      res.json({
        status: 'success',
        message: 'User data exported successfully',
        data: userData
      })
      
    } catch (error) {
      next(error)
    }
  }
}
