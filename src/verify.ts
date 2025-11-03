import { createHash } from "@better-auth/utils/hash";
import { createHMAC } from "@better-auth/utils/hmac";
import type { TelegramAuthData } from "./types";

/**
 * Verifies the authenticity of Telegram authentication data
 * @param data - Authentication data from Telegram Login Widget
 * @param botToken - Bot token from @BotFather
 * @param maxAge - Maximum age of auth in seconds (default: 24 hours)
 * @returns Promise<true> if data is valid, Promise<false> otherwise
 */
export async function verifyTelegramAuth(
  data: TelegramAuthData,
  botToken: string,
  maxAge = 86400
): Promise<boolean> {
  // Extract hash from data
  const { hash, ...dataWithoutHash } = data;

  // Check auth_date is not too old
  const authDate = dataWithoutHash.auth_date;
  const currentTime = Math.floor(Date.now() / 1000);

  if (currentTime - authDate > maxAge) {
    return false;
  }

  // Create data-check-string
  const dataCheckString = Object.keys(dataWithoutHash)
    .sort()
    .map((key) => {
      const value = dataWithoutHash[key as keyof typeof dataWithoutHash];
      return `${key}=${value}`;
    })
    .join("\n");

  // Create secret key: SHA256(bot_token)
  const secretKey = await createHash("SHA-256").digest(botToken);

  // Calculate HMAC-SHA256
  const hmac = createHMAC("SHA-256", "hex");
  const ck = await hmac.importKey(secretKey, "sign");
  const calculatedHash = await hmac.sign(ck, dataCheckString);

  // Compare with received hash
  return calculatedHash === hash;
}

/**
 * Verifies the authenticity of Telegram Mini App initData
 * @param initData - Raw initData string from Telegram.WebApp.initData
 * @param botToken - Bot token from @BotFather
 * @param maxAge - Maximum age of auth in seconds (default: 24 hours)
 * @returns Promise<true> if data is valid, false otherwise
 */
export async function verifyMiniAppInitData(
  initData: string,
  botToken: string,
  maxAge = 86400
): Promise<boolean> {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");

  if (!hash) {
    return false;
  }

  // Remove hash from params
  params.delete("hash");

  // Check auth_date
  const authDate = params.get("auth_date");
  if (!authDate) {
    return false;
  }

  const authDateNum = Number(authDate);
  const currentTime = Math.floor(Date.now() / 1000);

  if (currentTime - authDateNum > maxAge) {
    return false;
  }

  // Create data-check-string (sorted alphabetically)
  const dataCheckString = Array.from(params.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  // Create secret key: HMAC-SHA256("WebAppData", bot_token)
  const secretKey = await createHMAC("SHA-256").sign("WebAppData", botToken);

  // Calculate HMAC-SHA256
  const hmac = createHMAC("SHA-256", "hex");
  const ck = await hmac.importKey(secretKey, "sign");
  const calculatedHash = await hmac.sign(ck, dataCheckString);

  // Compare with received hash
  return calculatedHash === hash;
}
