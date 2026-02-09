import rateLimit from 'express-rate-limit';
import { logger } from '@/utils/logger.js';

const createRateLimiter = (windowMs: number, max: number, message: string) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      success: false,
      code: 'RATE_LIMIT_EXCEEDED',
      message,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        path: req.path,
      });

      res.status(429).json({
        success: false,
        code: 'RATE_LIMIT_EXCEEDED',
        message,
      });
    },
  });
};

export const loginRateLimiter = createRateLimiter(
  15 * 60 * 1000,
  10,
  'Too many login attempts. Please try again in 15 minutes.'
);

export const registerRateLimiter = createRateLimiter(
  24 * 60 * 60 * 1000,
  5,
  'Too many registration attempts. Please try again later.'
);

export const refreshRateLimiter = createRateLimiter(
  1 * 60 * 1000,
  10,
  'Too many refresh attempts. Please slow down.'
);


export const apiRateLimiter = createRateLimiter(
  1 * 60 * 1000,
  120,
  'Too many requests. Please slow down.'
);

export const authApiRateLimiter = createRateLimiter(
  1 * 60 * 1000,
  300,
  'Too many requests. Please slow down.'
);

export const passwordResetRateLimiter = createRateLimiter(
  60 * 60 * 1000, // 1 hour
  3, // 3 requests
  'Too many password reset requests, please try again later'
);