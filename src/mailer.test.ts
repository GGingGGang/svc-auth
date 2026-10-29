import { describe, expect, it, vi } from "vitest";
import { createSmtpSender, decryptMailPayload, encryptMailPayload, type MailConfig } from "./mailer.js";

describe("encrypted durable email payload", () => {
  const key = Buffer.alloc(32, 7);
  it("round-trips and rejects tampering", () => {
    const ciphertext = encryptMailPayload("{\"token\":\"secret\"}", key);
    expect(decryptMailPayload(ciphertext, key)).toBe("{\"token\":\"secret\"}");
    ciphertext[ciphertext.length - 1] ^= 1;
    expect(() => decryptMailPayload(ciphertext, key)).toThrow();
  });

  it("uses a URL fragment for the single-use token and can be tested with a fake transport", async () => {
    const sendMail = vi.fn().mockResolvedValue({ messageId: "fake" });
    const config: MailConfig = { smtpUrl: "smtp://example.invalid", from: "auth@example.invalid", encryptionKey: key, webUrl: "https://app.example.invalid" };
    const sender = createSmtpSender(config, { sendMail } as never);
    await sender("nobody@example.invalid", { subject: "Verify", token: "secret-token", action: "verify" });
    const message = sendMail.mock.calls[0]![0] as { to: string; text: string };
    expect(message.to).toBe("nobody@example.invalid");
    expect(message.text).toContain("#token=secret-token&action=verify");
    expect(message.text).not.toContain("?token=");
  });
});
