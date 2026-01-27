import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface AuthRequest extends Request {
  user?: {
    userId: string;
    role: "USER" | "ADMIN";
    sessionId?:  string
  };
}

export function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: No token" });
  }

  try {
    const token = header.split(" ")[1];

    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!) as {
      userId: string;
      role: "USER" | "ADMIN";
      sessionId?: string; 
    };

    req.user = {
      userId: payload.userId,
      role: payload.role,
      sessionId: payload.sessionId,
    };

    next();
  } catch (err: any) {
    console.error("JWT verification error:", err.message); 
    res.status(401).json({ message: "Invalid token" });
  }
}
