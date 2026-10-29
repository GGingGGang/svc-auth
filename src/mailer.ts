import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import nodemailer, { type Transporter } from "nodemailer";

export interface MailConfig { smtpUrl: string; from: string; encryptionKey: Buffer; webUrl: string }

export function loadMailConfig(env: NodeJS.ProcessEnv = process.env): MailConfig | null {
  if (!env.SMTP_URL || !env.SMTP_FROM || !env.AUTH_MAIL_ENCRYPTION_KEY || !env.WEB_APP_URL) return null;
  const encryptionKey = Buffer.from(env.AUTH_MAIL_ENCRYPTION_KEY, "base64");
  if (encryptionKey.length !== 32) throw new Error("AUTH_MAIL_ENCRYPTION_KEY must be a base64 32-byte key");
  return { smtpUrl: env.SMTP_URL, from: env.SMTP_FROM, encryptionKey, webUrl: env.WEB_APP_URL.replace(/\/$/u, "") };
}

export function encryptMailPayload(payload: string, key: Buffer): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(payload, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
}

export function decryptMailPayload(payload: Buffer, key: Buffer): string {
  const decipher = createDecipheriv("aes-256-gcm", key, payload.subarray(0, 12));
  decipher.setAuthTag(payload.subarray(12, 28));
  return Buffer.concat([decipher.update(payload.subarray(28)), decipher.final()]).toString("utf8");
}

export interface MailMessage { subject: string; token: string; action: "verify" | "reset" | "email-change" }
export type MailSender = (recipient: string, message: MailMessage) => Promise<void>;

export function createSmtpSender(config: MailConfig, transport?: Transporter): MailSender {
  const client = transport ?? nodemailer.createTransport(config.smtpUrl);
  return async (recipient, message) => {
    const link = `${config.webUrl}/account/action#token=${encodeURIComponent(message.token)}&action=${message.action}`;
    await client.sendMail({
      from: config.from,
      to: recipient,
      subject: message.subject,
      text: `Continue securely: ${link}\nThis link expires shortly and can only be used once.`,
    });
  };
}
