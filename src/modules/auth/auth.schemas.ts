import { z } from 'zod';

const PASSWORD_REGEX = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]/;

export const PasswordSchema = z
  .string({ message: 'Password is required' })
  .min(8, { message: 'Password must be at least 8 characters' })
  .max(128, { message: 'Password must not exceed 128 characters' })
  .regex(PASSWORD_REGEX, {
    message: 'Password must contain at least one letter, one number, and one special character',
  });

export const RegisterSchema = z.object({
  name: z
    .string({ message: 'Name is required' })
    .min(3, { message: 'Name must be at least 3 characters' })
    .max(50, { message: 'Name must not exceed 50 characters' })
    .transform((val) => val.trim()),

  email: z
    .string({ message: 'Email is required' })
    .email({ message: 'Invalid email format' })
    .transform((val) => val.toLowerCase().trim()),

  password: PasswordSchema,

  role: z
    .enum(['USER', 'ADMIN'], {
      message: 'Role must be either USER or ADMIN',
    })
    .optional()
    .default('USER'),
});

export const LoginSchema = z.object({
  email: z
    .string({ message: 'Email is required' })
    .email({ message: 'Invalid email format' })
    .transform((val) => val.toLowerCase().trim()),

  password: z
    .string({ message: 'Password is required' })
    .min(1, { message: 'Password is required' }),
});

export const RefreshSchema = z.object({
  refreshToken: z
    .string({ message: 'Refresh token is required' })
    .min(1, { message: 'Refresh token cannot be empty' }),
});

export const ForgotPasswordSchema = z.object({
  email: z
    .string({ message: 'Email is required' })
    .email({ message: 'Invalid email format' })
    .transform((val) => val.toLowerCase().trim()),
});

export const ResetPasswordSchema = z.object({
  token: z
    .string({ message: 'Reset token is required' })
    .min(1, { message: 'Reset token is required' }),

  password: PasswordSchema,

  confirmPassword: z
    .string({ message: 'Password confirmation is required' })
    .min(1, { message: 'Password confirmation is required' }),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

export const ChangePasswordSchema = z.object({
  currentPassword: z
    .string({ message: 'Current password is required' })
    .min(1, { message: 'Current password is required' }),

  newPassword: PasswordSchema,

  confirmPassword: z
    .string({ message: 'Password confirmation is required' })
    .min(1, { message: 'Password confirmation is required' }),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
}).refine((data) => data.currentPassword !== data.newPassword, {
  message: 'New password must be different from current password',
  path: ['newPassword'],
});

export type RegisterDto = z.infer<typeof RegisterSchema>;
export type LoginDto = z.infer<typeof LoginSchema>;
export type RefreshDto = z.infer<typeof RefreshSchema>;
export type ForgotPasswordDto = z.infer<typeof ForgotPasswordSchema>;
export type ResetPasswordDto = z.infer<typeof ResetPasswordSchema>;
export type ChangePasswordDto = z.infer<typeof ChangePasswordSchema>;