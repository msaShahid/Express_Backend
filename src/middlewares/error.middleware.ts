import { Request, Response, NextFunction } from "express";
import { ApiError } from "@/utils/api-error.js";

export function errorHandler(err: any,_req: Request,res: Response,_next: NextFunction) {

  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      success: false,
      message: err.message,
      code: err.code,
      details: err.details ?? null,
    });
  }

  console.error(err);

  res.status(500).json({
    success: false,
    message: "Internal server error",
    code: "INTERNAL_ERROR",
  });
  
}
