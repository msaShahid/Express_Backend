import bcrypt from "bcryptjs";

const SALT_ROUNDS = 12;

async function hash(value: string): Promise<string> {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return bcrypt.hash(value, salt);
}

export async function hashPassword(password: string): Promise<string> {
  return hash(password);
}

export async function hashToken(token: string): Promise<string> {
  return hash(token);
}

export async function compareHash(value: string, hash: string): Promise<boolean> {
  return bcrypt.compare(value, hash);
}
