import { PKPass } from "passkit-generator";
import { readFileSync, writeFileSync } from "fs";
import path from "path";
import { randomUUID, createHmac } from "crypto";
import "dotenv/config";

const rawToken = "evt_28ede670_prt_0dd1d08a_cdf7e4767939";

// 1. HMAC署名
const sig = createHmac("sha256", process.env.HMAC_SECRET)
  .update(rawToken)
  .digest("base64url");

// 2. signedTokenを作成
const signedToken = `${rawToken}.${sig}`;

// 3. base64urlエンコード
const encodedToken = Buffer.from(signedToken).toString("base64url");

console.log("rawToken:", rawToken);
console.log("sig:", sig);
console.log("signedToken:", signedToken);
console.log("encodedToken:", encodedToken);
console.log("URL:", `http://localhost:3000/api/pass?token=${encodedToken}`);

const pass = await PKPass.from(
  {
    model: path.join(process.cwd(), "passes/MyPass.pass"),
    certificates: {
      wwdr: readFileSync("certs/wwdr.pem"),
      signerCert: readFileSync("certs/signerCert.pem"),
      signerKey: readFileSync("certs/signerKey.pem"),
      signerKeyPassphrase: process.env.SIGNER_KEY_PASSPHRASE,
    },
  },
  {
    serialNumber: randomUUID(),
  }
);

pass.setBarcodes({
  message: rawToken,
  format: "PKBarcodeFormatQR",
  messageEncoding: "iso-8859-1",
});

const buf = pass.getAsBuffer();
writeFileSync("test.pkpass", buf);
console.log("test.pkpass を生成しました！");