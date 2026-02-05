import { Router } from 'express';
import { AuthController } from './auth.controller.js';
import { RegisterSchema, LoginSchema, RefreshSchema } from './auth.schemas.js';
import { authenticate } from '@/middlewares/auth.middleware.js';
import { validateRequest } from '@/middlewares/validation.middleware.js';
import { authApiRateLimiter, loginRateLimiter, refreshRateLimiter, registerRateLimiter } from '@/middlewares/rate-limit.middleware.js';

const router = Router();

router.post(
  '/register',
  registerRateLimiter,
  validateRequest(RegisterSchema),
  AuthController.register
);

router.post(
  '/login',
  loginRateLimiter,
  validateRequest(LoginSchema),
  AuthController.login
);

router.post(
  '/refresh',
  refreshRateLimiter, 
  validateRequest(RefreshSchema),
  AuthController.refresh
);

router.post(
  '/logout',
  authenticate,       
  authApiRateLimiter,
  AuthController.logout
);

router.get(
  '/me',
  authenticate,       
  authApiRateLimiter,
  AuthController.me
);

export default router;