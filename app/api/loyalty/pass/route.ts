// app/api/loyalty/pass/route.ts
export const runtime = "nodejs";

import JSZip from "jszip";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

/**
 * REQUIRED ENV VARS (set in Vercel → Project → Settings → Environment Variables):
 *
 * - CASA_APP_API_KEY
 *
 * Apple Wallet signing (one of these approaches):
 * Option A (recommended): base64 strings
 * - PASS_TYPE_ID_CERT_P12_BASE64
 * - PASS_TYPE_ID_CERT_P12_PASSWORD
 * - WWDR_CERT_PEM_BASE64
 *
 * Option B: provide PEM paths or other approach (not shown)
 *
 * Pass metadata:
 * - PASS_TYPE_IDENTIFIER
 * - TEAM_IDENTIFIER
 * - ORGANIZATION_NAME
 * - DESCRIPTION
 *
 * Optional:
 * - PASS_BACKGROUND_COLOR (e.g. "rgb(14, 153, 130)")
 * - PASS_FOREGROUND_COLOR (e.g. "rgb(255,255,255)")
 * - PASS_LABEL_COLOR: (e.g. "rgb(255,255,255)")
 *
 * Assets (base64):
 * - PASS_ICON_PNG_BASE64
 * - PASS_LOGO_PNG_BASE64 (optional)
 */

type RequestBody = {
  serial?: string;
  memberName?: string;
  memberId?: string;
  tierName?: string;
  points?: number;
};

function b64ToBuffer(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}

function sha1(buf: Buffer | Uint8Array): string {
  return crypto.createHash("sha1").update(buf).digest("hex");
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

function sanitizeSerial(input?: string): string {
  const base = (input || crypto.randomUUID()).trim();
  // keep it safe for filename + pass serial
  return base.replace(/[^a-zA-Z0-9._-]/g, "-").slice(0, 64);
}

async function writeTempFile(dir: string, filename: string, data: Buffer) {
  const p = path.join(dir, filename);
  await fs.promises.writeFile(p, data);
  return p;
}

// Sign manifest.json with OpenSSL using Pass Type ID cert + WWDR.
// This produces the "signature" file required by Apple Wallet passes.
async function signManifest(params: {
  tmpDir: string;
  manifestPath: string;
}): Promise<Buffer> {
  const p12b64 = requireEnv("PASS_TYPE_ID_CERT_P12_BASE64");
  const p12pass = requireEnv("PASS_TYPE_ID_CERT_P12_PASSWORD");
  const wwdrPemB64 = requireEnv("WWDR_CERT_PEM_BASE64");

  const p12Path = await writeTempFile(params.tmpDir, "passcert.p12", b64ToBuffer(p12b64));
  const wwdrPath = await writeTempFile(params.tmpDir, "wwdr.pem", b64ToBuffer(wwdrPemB64));

  const signerKeyPath = path.join(params.tmpDir, "signer.key.pem");
  const signerCertPath = path.join(params.tmpDir, "signer.cert.pem");
  const signaturePath = path.join(params.tmpDir, "signature");

  // Extract key + cert from p12
  // key
  await execFileAsync("openssl", [
    "pkcs12",
    "-in",
    p12Path,
    "-nocerts",
    "-out",
    signerKeyPath,
    "-passin",
    `pass:${p12pass}`,
    "-passout",
    "pass:",
  ]);

  // cert
  await execFileAsync("openssl", [
    "pkcs12",
    "-in",
    p12Path,
    "-clcerts",
    "-nokeys",
    "-out",
    signerCertPath,
    "-passin",
    `pass:${p12pass}`,
  ]);

  // Sign manifest.json (PKCS7 detached signature)
  await execFileAsync("openssl", [
    "smime",
    "-binary",
    "-sign",
    "-certfile",
    wwdrPath,
    "-signer",
    signerCertPath,
    "-inkey",
    signerKeyPath,
    "-in",
    params.manifestPath,
    "-out",
    signaturePath,
    "-outform",
    "DER",
    "-nodetach",
  ]);

  return await fs.promises.readFile(signaturePath);
}

export async function POST(req: Request) {
  // temp workspace for openssl + intermediate files
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pkpass-"));

  try {
    // ---- auth ----
    const expectedKey = requireEnv("CASA_APP_API_KEY");
    const gotKey =
      req.headers.get("x-api-key") ||
      req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ||
      "";

    if (!gotKey || gotKey !== expectedKey) {
      return new Response("Unauthorized", { status: 401 });
    }

    // ---- input ----
    const body = (await req.json().catch(() => ({}))) as RequestBody;

    const serial = sanitizeSerial(body.serial);
    const memberName = body.memberName?.trim() || "Casa Marana Member";
    const memberId = body.memberId?.trim() || "—";
    const tierName = body.tierName?.trim() || "Starter";
    const points = Number.isFinite(body.points) ? Number(body.points) : 0;

    // ---- pass.json ----
    const passTypeIdentifier = requireEnv("PASS_TYPE_IDENTIFIER");
    const teamIdentifier = requireEnv("TEAM_IDENTIFIER");
    const organizationName = requireEnv("ORGANIZATION_NAME");
    const description = requireEnv("DESCRIPTION");

    const backgroundColor = process.env.PASS_BACKGROUND_COLOR || "rgb(14, 153, 130)";
    const foregroundColor = process.env.PASS_FOREGROUND_COLOR || "rgb(255,255,255)";
    const labelColor = process.env.PASS_LABEL_COLOR || "rgb(255,255,255)";

    const passJson = {
      formatVersion: 1,
      passTypeIdentifier,
      serialNumber: serial,
      teamIdentifier,
      organizationName,
      description,

      backgroundColor,
      foregroundColor,
      labelColor,

      // You can customize these later
      logoText: "Casa Marana",
      barcode: {
        message: memberId,
        format: "PKBarcodeFormatQR",
        messageEncoding: "iso-8859-1",
      },

      // Use "storeCard" / "eventTicket" etc as you prefer.
      storeCard: {
        primaryFields: [
          { key: "name", label: "Member", value: memberName },
        ],
        secondaryFields: [
          { key: "tier", label: "Tier", value: tierName },
          { key: "points", label: "Points", value: String(points) },
        ],
        auxiliaryFields: [
          { key: "id", label: "ID", value: memberId },
        ],
      },
    };

    const passJsonBuf = Buffer.from(JSON.stringify(passJson, null, 2), "utf8");

    // ---- assets ----
    const iconB64 = requireEnv("PASS_ICON_PNG_BASE64");
    const iconPng = b64ToBuffer(iconB64);

    const logoB64 = process.env.PASS_LOGO_PNG_BASE64;
    const logoPng = logoB64 ? b64ToBuffer(logoB64) : null;

    // ---- manifest.json ----
    const manifest: Record<string, string> = {};
    manifest["pass.json"] = sha1(passJsonBuf);
    manifest["icon.png"] = sha1(iconPng);
    if (logoPng) manifest["logo.png"] = sha1(logoPng);

    const manifestBuf = Buffer.from(JSON.stringify(manifest, null, 2), "utf8");

    const manifestPath = path.join(tmpDir, "manifest.json");
    await fs.promises.writeFile(manifestPath, manifestBuf);

    // ---- signature ----
    const signatureBuf = await signManifest({ tmpDir, manifestPath });

    // ---- zip into .pkpass ----
    const zip = new JSZip();
    zip.file("pass.json", passJsonBuf);
    zip.file("icon.png", iconPng);
    if (logoPng) zip.file("logo.png", logoPng);
    zip.file("manifest.json", manifestBuf);
    zip.file("signature", signatureBuf);

    const pkpass = await zip.generateAsync({ type: "uint8array", compression: "DEFLATE" });

    // ✅ IMPORTANT: pkpass is Uint8Array => valid BodyInit for Response in Next.js
    return new Response(pkpass, {
      status: 200,
      headers: {
        "Content-Type": "application/vnd.apple.pkpass",
        "Content-Disposition": `attachment; filename="casa-marana-${serial}.pkpass"`,
        "Cache-Control": "no-store",
      },
    });
  } catch (e: any) {
    const msg = e?.message || "Unknown error";
    return new Response(msg, { status: 500 });
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
}
