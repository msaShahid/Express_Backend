export interface AuthResponse {
  user: {
    id: string;
    name: string;
    email: string;
    role: string;
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
  };
}

export interface RequestMetadata {
  ipAddress: string | null;
  userAgent: string | null;
}