import { Request, Response } from "express";
import { AuthService } from "./auth.service.js";
import { RegisterSchema, LoginSchema, RefreshSchema } from "./auth.schemas.js";
import { AuthRequest } from "@/middlewares/auth.middleware.js";

export class AuthController {
  
  static async register(req: Request, res: Response) {
    try {
      const parsed = RegisterSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid input" });
      }

      const tokens = await AuthService.register(parsed.data);
      res.status(201).json(tokens);
    } catch (err: any) {
      res.status(400).json({ message: err.message });
    }
  }

  static async login(req: Request, res: Response) {
    try {
      const parsed = LoginSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid input" });
      }

      const tokens = await AuthService.login(parsed.data);
      res.json(tokens);
    } catch (err: any) {
      res.status(401).json({ message: err.message });
    }
  }

  static async refresh(req: Request, res: Response) {
    try {
      const parsed = RefreshSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid input" });
      }

      const tokens = await AuthService.refresh(parsed.data.refreshToken);
      res.json(tokens);
    } catch (err: any) {
      res.status(401).json({ message: err.message });
    }
  }

  static async logout(req: AuthRequest, res: Response) {
    try {
      const userId = req.user!.userId;
      await AuthService.logout(userId);
      res.json({ message: "Logged out successfully" });
    } catch (err: any) {
      res.status(400).json({ message: err.message });
    }
  }
}
