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
  5,
  'Too many login attempts, please try again later'
);

export const registerRateLimiter = createRateLimiter(
  60 * 60 * 1000,
  3,
  'Too many registration attempts, please try again later'
);

export const apiRateLimiter = createRateLimiter(
  15 * 60 * 1000,
  100,
  'Too many requests, please try again later'
);