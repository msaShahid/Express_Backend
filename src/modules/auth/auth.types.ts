export interface RegisterDto {
  name: string,
  email: string;
  password: string;
  role?: "USER" | "ADMIN"; 
}

export interface LoginDto {
  email: string;
  password: string;
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
}

export interface UserResponse {
  id: string;
  name: string,
  email: string;
  role: "USER" | "ADMIN";
  emailVerified?: boolean;
  failedLoginAttempts: number
  isActive?: boolean;
  createdAt?: Date;
}

export interface AuthResponse {
  user: UserResponse;
  accessToken: string;
  refreshToken: string;
}