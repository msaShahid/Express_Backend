import { AuthRepository } from "./auth.repository.js";
import { LoginDto, Tokens, RegisterDto, AuthResponse } from "./auth.types.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "./utils/jwt.js";
import { compareHash, hashPassword, hashToken } from "./utils/password.js";

export class AuthService {

  static async register(dto: RegisterDto): Promise<AuthResponse> {
    const existingUser = await AuthRepository.findUserByEmail(dto.email);
    if (existingUser) throw new Error("Email already registered");

    const passwordHash = await hashPassword(dto.password);

    const user = await AuthRepository.createUser({
      email: dto.email,
      passwordHash,
      role: dto.role,
    });

    const accessToken = signAccessToken({ userId: user.id, role: user.role });
    const refreshToken = signRefreshToken({ userId: user.id });
    const tokenHash = await hashToken(refreshToken);

    await AuthRepository.createRefreshToken({
      userId: user.id,
      tokenHash,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified,
        isActive: user.isActive,
        createdAt: user.createdAt,

      },
      accessToken,
      refreshToken,
    };
  }

  static async login(dto: LoginDto): Promise<AuthResponse> {
    const user = await AuthRepository.findUserByEmail(dto.email);
    if (!user) throw new Error("Invalid credentials");
    if (!user.isActive) throw new Error("User is inactive");

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new Error("Account temporarily locked");
    }

    const validPassword = await compareHash(dto.password, user.passwordHash);

    if (!validPassword) {
      const attempts = user.failedLoginAttempts + 1;

      if (attempts >= 5) {
        await AuthRepository.lockUser(
          user.id,
          new Date(Date.now() + 15 * 60 * 1000)
        );
      } else {
        await AuthRepository.incrementFailedAttempts(user.id);
      }

      throw new Error("Invalid credentials");
    }

    await AuthRepository.resetFailedAttempts(user.id);

    const accessToken = signAccessToken({ userId: user.id, role: user.role });
    const refreshToken = signRefreshToken({ userId: user.id });

    await AuthRepository.createRefreshToken({
      userId: user.id,
      tokenHash: await hashToken(refreshToken),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified,
        isActive: user.isActive,
        createdAt: user.createdAt,

      },
      accessToken,
      refreshToken,
    };

  }


  static async refresh(token: string): Promise<AuthResponse> {
    const payload = verifyRefreshToken(token) as { userId: string };

    const user = await AuthRepository.findUserById(payload.userId);
    if (!user) throw new Error("User not found");

    const dbToken = await AuthRepository.findLatestRefreshToken(user.id);
    if (!dbToken) throw new Error("Invalid refresh token");

    const valid = await compareHash(token, dbToken.tokenHash);
    if (!valid) throw new Error("Invalid refresh token");

    const accessToken = signAccessToken({
      userId: user.id,
      role: user.role,
    });

    const refreshToken = signRefreshToken({ userId: user.id });

    await AuthRepository.createRefreshToken({
      userId: user.id,
      tokenHash: await hashToken(refreshToken),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    await AuthRepository.deleteRefreshToken(dbToken.id);

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified,
        isActive: user.isActive,
        createdAt: user.createdAt,

      },
      accessToken,
      refreshToken,
    };
  }

  static async logout(userId: string) {
    await AuthRepository.deleteAllRefreshTokens(userId);
    return { message: "Logged out successfully" };
  }
}
