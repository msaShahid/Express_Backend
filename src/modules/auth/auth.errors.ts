import { ApiError } from '@/utils/api-error.js';

export const AuthErrors = {
  EMAIL_EXISTS: () =>
    new ApiError(409, 'Email already registered', 'EMAIL_EXISTS'),

  INVALID_CREDENTIALS: () =>
    new ApiError(401, 'Invalid email or password', 'INVALID_CREDENTIALS'),

  USER_INACTIVE: () =>
    new ApiError(403, 'User account is inactive', 'USER_INACTIVE'),

  ACCOUNT_LOCKED: (until: Date) =>
    new ApiError(423, 'Account temporarily locked', 'ACCOUNT_LOCKED', {
      lockedUntil: until,
    }),

  INVALID_REFRESH_TOKEN: () =>
    new ApiError(401, 'Invalid refresh token', 'INVALID_REFRESH_TOKEN'),

  USER_NOT_FOUND: () =>
    new ApiError(404, 'User not found', 'USER_NOT_FOUND'),

  UNAUTHORIZED: () =>
    new ApiError(401, 'Unauthorized access', 'UNAUTHORIZED'),

  TOKEN_EXPIRED: () =>
    new ApiError(401, 'Token has expired', 'TOKEN_EXPIRED'),

  WEAK_PASSWORD: () =>
    new ApiError(
      400,
      'Password does not meet security requirements',
      'WEAK_PASSWORD'
    ),
    
  EMAIL_NOT_VERIFIED: () =>
    new ApiError(403, 'Please verify your email first', 'EMAIL_NOT_VERIFIED'),
  
  INVALID_RESET_TOKEN: () =>
    new ApiError(400, 'Invalid or expired reset token', 'INVALID_RESET_TOKEN'),

  RESET_TOKEN_EXPIRED: () =>
    new ApiError(400, 'Reset token has expired', 'RESET_TOKEN_EXPIRED'),

  RESET_TOKEN_ALREADY_USED: () =>
    new ApiError(400, 'Reset token has already been used', 'RESET_TOKEN_ALREADY_USED'),

  SAME_PASSWORD: () =>
    new ApiError(400, 'New password must be different from current password', 'SAME_PASSWORD'),

  RATE_LIMIT_RESET: () =>
    new ApiError(429, 'Too many password reset requests. Please try again later.', 'RATE_LIMIT_RESET'),

};