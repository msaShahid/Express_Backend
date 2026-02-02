import { ZodError } from 'zod';

export interface FormattedValidationError {
  field: string;
  message: string;
}

export function formatZodError(error: ZodError): FormattedValidationError[] {
  return error.issues.map((issue) => ({
    field: issue.path.join('.') || 'root',
    message: issue.message,
  }));
}

export function createValidationErrorResponse(error: ZodError) {
  return {
    success: false,
    code: 'VALIDATION_ERROR',
    message: 'Invalid input',
    errors: formatZodError(error),
  };
}
