import { Request, Response, NextFunction } from 'express';
import { ZodType } from 'zod';
import { createValidationErrorResponse } from '@/utils/validation.js';

export const validateRequest =
  <T>(schema: ZodType<T>) =>
  (req: Request, res: Response, next: NextFunction) => {
    const parsed = schema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(422).json(createValidationErrorResponse(parsed.error));
    }

    req.body = parsed.data as T;
    next();
  };
