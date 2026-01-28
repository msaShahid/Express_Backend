import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";

export interface AuthRequest extends Request {
  user?: {
    userId: string;
    role: "USER" | "ADMIN";
    sessionId: string;
  };
}

interface AccessTokenPayload extends JwtPayload {
  userId: string;
  role: "USER" | "ADMIN";
  sessionId: string;
}

export function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      code: "NO_TOKEN",
      message: "Authorization token missing",
    });
  }

  const token = header.split(" ")[1];

  try {
    const payload = jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET!,
      {
        clockTolerance: 5, // 5 seconds skew tolerance
      }
    ) as AccessTokenPayload;

    req.user = {
      userId: payload.userId,
      role: payload.role,
      sessionId: payload.sessionId,
    };

    next();
  } catch (err: unknown) {
    if (err && typeof err === "object" && "name" in err && err.name === "TokenExpiredError") {
      return res.status(401).json({
        code: "TOKEN_EXPIRED",
        message: "Access token expired",
      });
    }

    return res.status(401).json({
      code: "INVALID_TOKEN",
      message: "Invalid access token",
    });
  }

}
