export class ApiError extends Error {
  statusCode: number;
  code: string;
  data?: Record<string, any>;
  isOperational: boolean;

  constructor(
    statusCode: number,
    message: string,
    code: string,
    data?: Record<string, any>,
    isOperational = true
  ) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = code;
    this.data = data;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}