import { Request, Response, NextFunction } from 'express';
import { AuthService } from './auth.service.js';
import { AuthRequest } from '@/middlewares/auth.middleware.js';
import { ChangePasswordSchema, ForgotPasswordSchema, ResetPasswordSchema } from './auth.schemas.js';
import { createValidationErrorResponse } from '@/utils/validation.js';

export class AuthController {

  static async register(req: Request, res: Response, next: NextFunction) {
    try {
      const data = await AuthService.register(req.body, req);

      res.status(201).json({
        success: true,
        message: 'Registration successful',
        data,
      });
    } catch (error) {
      next(error);
    }
  }

  static async login(req: Request, res: Response, next: NextFunction) {
    try {
      const data = await AuthService.login(req.body, req);

      res.status(200).json({
        success: true,
        message: 'Login successful',
        data,
      });
    } catch (error) {
      next(error);
    }
  }

  static async refresh(req: Request, res: Response, next: NextFunction) {
    try {
      const data = await AuthService.refresh(req.body.refreshToken);

      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        data,
      });
    } catch (error) {
      next(error);
    }
  }

  static async logout(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      await AuthService.logout(req.user!.userId, req.user?.sessionId);

      res.status(200).json({
        success: true,
        message: req.user?.sessionId
          ? 'Logged out from this device'
          : 'Logged out from all devices',
      });
    } catch (error) {
      next(error);
    }
  }

  static async me(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      res.status(200).json({
        success: true,
        user: {
          id: req.user!.userId,
          role: req.user!.role,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  static async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const parsed = ForgotPasswordSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(422).json(createValidationErrorResponse(parsed.error));
      }

      const data = await AuthService.forgotPassword(parsed.data, req);

      res.status(200).json({
        success: true,
        message: data.message,
      });
    } catch (error) {
      next(error);
    }
  }

  static async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const parsed = ResetPasswordSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(422).json(createValidationErrorResponse(parsed.error));
      }

      const data = await AuthService.resetPassword(parsed.data, req);

      res.status(200).json({
        success: true,
        message: data.message,
      });
    } catch (error) {
      next(error);
    }
  }

  static async changePassword(
    req: AuthRequest,
    res: Response,
    next: NextFunction
  ) {
    try {
      const parsed = ChangePasswordSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(422).json(createValidationErrorResponse(parsed.error));
      }

      const data = await AuthService.changePassword(
        req.user!.userId,
        parsed.data,
        req
      );

      res.status(200).json({
        success: true,
        message: data.message,
      });
    } catch (error) {
      next(error);
    }
  }

}