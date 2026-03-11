import { PKPass } from "passkit-generator";
import { readFileSync } from "fs";
import path from "path";
import { randomUUID, createHmac, timingSafeEqual } from "crypto";

export default async function handler(req, res) {
  const { token: encodedToken } = req.query;

  if (!encodedToken) {
    return res.status(400).json({ error: "token is required" });
  }

  // 1. base64urlデコード
  const signedToken = Buffer.from(encodedToken, "base64url").toString("utf-8");

  // 2. ドットで分割
  const delimIdx = signedToken.lastIndexOf(".");
  if (delimIdx === -1) {
    return res.status(400).json({ error: "invalid token format" });
  }
  const rawToken = signedToken.substring(0, delimIdx);
  const providedSig = signedToken.substring(delimIdx + 1);

  // 3. HMAC検証
  const expected = createHmac("sha256", process.env.HMAC_SECRET)
    .update(rawToken)
    .digest("base64url");

  try {
    if (!timingSafeEqual(Buffer.from(providedSig), Buffer.from(expected))) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const signerCert = process.env.SIGNER_CERT
      ? Buffer.from(process.env.SIGNER_CERT, "base64")
      : readFileSync(path.join(process.cwd(), "certs/signerCert.pem"));

    const signerKey = process.env.SIGNER_KEY
      ? Buffer.from(process.env.SIGNER_KEY, "base64")
      : readFileSync(path.join(process.cwd(), "certs/signerKey.pem"));

    const wwdr = process.env.WWDR_CERT
      ? Buffer.from(process.env.WWDR_CERT, "base64")
      : readFileSync(path.join(process.cwd(), "certs/wwdr.pem"));

    const pass = await PKPass.from(
      {
        model: path.join(process.cwd(), "passes/MyPass.pass"),
        certificates: {
          wwdr,
          signerCert,
          signerKey,
          signerKeyPassphrase: process.env.SIGNER_KEY_PASSPHRASE || "",
        },
      },
      {
        serialNumber: randomUUID(),
      }
    );

    // signedTokenをQRに埋め込む
    pass.setBarcodes({
      message: signedToken,
      format: "PKBarcodeFormatQR",
      messageEncoding: "iso-8859-1",
    });

    const buf = pass.getAsBuffer();

    res.setHeader("Content-Type", "application/vnd.apple.pkpass");
    res.setHeader("Content-Disposition", `attachment; filename="pass.pkpass"`);
    res.send(buf);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
}
