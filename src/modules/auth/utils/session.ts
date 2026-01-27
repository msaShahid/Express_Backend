import crypto from "crypto";

export function generateSessionId() {
  return crypto.randomUUID();
}
