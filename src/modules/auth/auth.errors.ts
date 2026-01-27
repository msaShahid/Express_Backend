import { ApiError } from "@/utils/api-error.js";

export const AuthErrors = {
  EMAIL_EXISTS: () =>
    new ApiError(409, "Email already registered", "EMAIL_EXISTS"),

  INVALID_CREDENTIALS: () =>
    new ApiError(401, "Invalid email or password", "INVALID_CREDENTIALS"),

  USER_INACTIVE: () =>
    new ApiError(403, "User account is inactive", "USER_INACTIVE"),

  ACCOUNT_LOCKED: (until: Date) =>
    new ApiError(
      423,
      "Account temporarily locked",
      "ACCOUNT_LOCKED",
      { lockedUntil: until }
    ),

  INVALID_REFRESH_TOKEN: () =>
    new ApiError(401, "Invalid refresh token", "INVALID_REFRESH_TOKEN"),

  USER_NOT_FOUND: () =>
    new ApiError(404, "User not found", "USER_NOT_FOUND"),
};
