import { z } from "zod";

export const RegisterSchema = z.object({
  name: z.string().min(3),
  email: z.email(),
  password: z.string().min(5),
  role: z.enum(["USER", "ADMIN"]).optional(),
});

export const LoginSchema = z.object({
  email: z.email(),
  password: z.string().min(1),
});

export const RefreshSchema = z.object({
  refreshToken: z.string().min(1),
});
