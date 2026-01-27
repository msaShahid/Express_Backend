import { Request } from "express";

export function getRequestMeta(req: Request) {
  return {
    ipAddress:
      req.headers["x-forwarded-for"]?.toString().split(",")[0] ||
      req.socket.remoteAddress ||
      null,

    userAgent: req.headers["user-agent"] || null,
  };
}
