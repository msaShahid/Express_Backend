import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { AuthErrors } from '@/modules/auth/auth.errors.js';
import { logger } from '@/utils/logger.js';
import { AccessTokenPayload } from '@/modules/auth/utils/jwt.js';

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!;
const ISSUER = 'myapp-auth';
const AUDIENCE = 'myapp-client';

export interface AuthRequest extends Request {
  user?: AccessTokenPayload;
}

export const authenticate = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.warn('Missing or invalid authorization header', {
        path: req.path,
        ip: req.ip,
      });
      throw AuthErrors.UNAUTHORIZED();
    }

    const token = authHeader.substring(7);

    try {
      const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET, {
        issuer: ISSUER,
        audience: AUDIENCE,
        algorithms: ['HS256'],
      }) as AccessTokenPayload;

      req.user = decoded;
      next();
    } catch (error) {
      logger.warn('Token verification failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        path: req.path,
        ip: req.ip,
      });

      if (error instanceof Error && error.name === 'TokenExpiredError') {
        throw AuthErrors.TOKEN_EXPIRED();
      }

      throw AuthErrors.UNAUTHORIZED();
    }
  } catch (error) {
    next(error);
  }
};

export const authorize = (...allowedRoles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        throw AuthErrors.UNAUTHORIZED();
      }

      if (!allowedRoles.includes(req.user.role)) {
        logger.warn('Insufficient permissions', {
          userId: req.user.userId,
          role: req.user.role,
          required: allowedRoles,
          path: req.path,
        });

        return res.status(403).json({
          success: false,
          code: 'FORBIDDEN',
          message: 'Insufficient permissions',
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};