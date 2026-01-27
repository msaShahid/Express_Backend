import { Request, Response } from "express";
import { AuthService } from "./auth.service.js";
import { RegisterSchema, LoginSchema, RefreshSchema } from "./auth.schemas.js";
import { AuthRequest } from "@/middlewares/auth.middleware.js";

export class AuthController {

  static async register(req: Request, res: Response) {
    const parsed = RegisterSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(422).json({
        success: false,
        code: "VALIDATION_ERROR",
        message: "Invalid input",
        details: parsed.error.flatten(),
      });
    }

    try {
      const data = await AuthService.register(parsed.data, req);
      res.status(201).json({
        success: true,
        message: "Registration successful",
        data,
      });
    } catch (err: any) {
      res.status(400).json({
        success: false,
        code: "AUTH_ERROR",
        message: err.message,
      });
    }
  }

  static async login(req: Request, res: Response) {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(422).json({
        success: false,
        code: "VALIDATION_ERROR",
        message: "Invalid input",
      });
    }

    try {
      const data = await AuthService.login(parsed.data, req);
      res.status(200).json({
        success: true,
        message: "Login successful",
        data,
      });
    } catch (err: any) {
      res.status(401).json({
        success: false,
        code: "AUTH_ERROR",
        message: err.message,
      });
    }
  }

  static async refresh(req: Request, res: Response) {
    const parsed = RefreshSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(422).json({
        success: false,
        code: "VALIDATION_ERROR",
        message: "Invalid input",
      });
    }

    try {
      const data = await AuthService.refresh(parsed.data.refreshToken);
      res.status(200).json({
        success: true,
        message: "Token refreshed successfully",
        data,
      });
    } catch (err: any) {
      res.status(401).json({
        success: false,
        code: "AUTH_ERROR",
        message: err.message,
      });
    }
  }

  static async logout(req: AuthRequest, res: Response) {
    try {
      const sessionId = req.user?.sessionId;
      await AuthService.logout(req.user!.userId, sessionId);
      res.status(200).json({
        success: true,
        message: sessionId ? "Logged out from this device" : "Logged out from all devices",
      });
    } catch (err: any) {
      res.status(400).json({
        success: false,
        code: "AUTH_ERROR",
        message: err.message,
      });
    }
  }
}
