// app/api/loyalty/pass/route.ts
export const runtime = "nodejs";

import JSZip from "jszip";
import crypto from "crypto";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const forge: any = require("node-forge");
// ---------- Types ----------
type RequestBody = {
  serial?: string;
  memberName?: string;
  memberId?: string;
  tierName?: string;
  points?: number;
};

// ---------- Helpers ----------
function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

function b64ToBuffer(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}

function sha1Hex(data: Buffer | Uint8Array): string {
  return crypto.createHash("sha1").update(data).digest("hex");
}

function sanitizeSerial(input?: string): string {
  const base = (input || crypto.randomUUID()).trim();
  return base.replace(/[^a-zA-Z0-9._-]/g, "-").slice(0, 64);
}

function parseAuthKey(req: Request): string {
  return (
    req.headers.get("x-api-key") ||
    req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ||
    ""
  );
}

function parseGetBody(req: Request): RequestBody {
  const url = new URL(req.url);
  const p = url.searchParams;

  const pointsRaw = p.get("points");
  const points = pointsRaw !== null ? Number(pointsRaw) : undefined;

  return {
    serial: p.get("serial") ?? undefined,
    memberName: p.get("memberName") ?? undefined,
    memberId: p.get("memberId") ?? undefined,
    tierName: p.get("tierName") ?? undefined,
    points: Number.isFinite(points as number) ? (points as number) : undefined,
  };
}

/**
 * Extract the first PEM block from a string (handles "Bag Attributes" noise).
 */
function firstPemBlock(pemText: string): string {
  const m = pemText.match(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/m);
  if (!m) throw new Error("Invalid PEM content (no BEGIN/END block found).");
  return m[0];
}

/**
 * Create PKCS#7 detached signature (DER) for Wallet pass manifest.json using node-forge.
 * This replaces `openssl smime -sign -outform DER`.
 */
function signManifestDer(manifestBuf: Buffer): Buffer {
  const signerKeyPem = firstPemBlock(b64ToBuffer(requireEnv("SIGNER_KEY_PEM_BASE64")).toString("utf8"));
  const signerCertPem = firstPemBlock(b64ToBuffer(requireEnv("SIGNER_CERT_PEM_BASE64")).toString("utf8"));
  const wwdrCertPem = firstPemBlock(b64ToBuffer(requireEnv("WWDR_CERT_PEM_BASE64")).toString("utf8"));

  const signerCert = forge.pki.certificateFromPem(signerCertPem);
  const wwdrCert = forge.pki.certificateFromPem(wwdrCertPem);
  const signerKey = forge.pki.privateKeyFromPem(signerKeyPem);

  const p7 = forge.pkcs7.createSignedData();

  // forge expects "binary string" content
  const binaryStr = manifestBuf.toString("binary"); // latin1/binary
  p7.content = forge.util.createBuffer(binaryStr);

  // Include cert chain
  p7.addCertificate(signerCert);
  p7.addCertificate(wwdrCert);

  // Wallet passes use SHA-1
  p7.addSigner({
    key: signerKey,
    certificate: signerCert,
    digestAlgorithm: forge.pki.oids.sha1,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ],
  });

  // Detached signature required
  p7.sign({ detached: true });

  const derBytes = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(derBytes, "binary");
}

// ---------- Main ----------
async function generatePkpass(req: Request, body: RequestBody) {
  // --- auth ---
  const expectedKey = requireEnv("CASA_APP_API_KEY");
  const gotKey = parseAuthKey(req);

  if (!gotKey || gotKey !== expectedKey) {
    return new Response("Unauthorized", { status: 401 });
  }

  // --- inputs ---
  const serial = sanitizeSerial(body.serial);
  const memberName = body.memberName?.trim() || "Casa Marana Member";
  const memberId = body.memberId?.trim() || serial;
  const tierName = body.tierName?.trim() || "Starter";
  const points = Number.isFinite(body.points) ? Number(body.points) : 0;

  // --- metadata env ---
  const passTypeIdentifier = requireEnv("PASS_TYPE_IDENTIFIER");
  const teamIdentifier = requireEnv("TEAM_IDENTIFIER");
  const organizationName = requireEnv("ORGANIZATION_NAME");
  const description = requireEnv("DESCRIPTION");

  const backgroundColor = process.env.PASS_BACKGROUND_COLOR || "rgb(14, 153, 130)";
  const foregroundColor = process.env.PASS_FOREGROUND_COLOR || "rgb(255,255,255)";
  const labelColor = process.env.PASS_LABEL_COLOR || "rgb(255,255,255)";

  // --- pass.json ---
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

    logoText: "Casa Marana",
    barcode: {
      message: memberId,
      format: "PKBarcodeFormatQR",
      messageEncoding: "iso-8859-1",
    },

    storeCard: {
      primaryFields: [{ key: "name", label: "Member", value: memberName }],
      secondaryFields: [
        { key: "tier", label: "Tier", value: tierName },
        { key: "points", label: "Points", value: String(points) },
      ],
      auxiliaryFields: [{ key: "id", label: "ID", value: memberId }],
    },
  };

  const passJsonBuf = Buffer.from(JSON.stringify(passJson, null, 2), "utf8");

  // --- assets ---
  const iconPng = b64ToBuffer(requireEnv("PASS_ICON_PNG_BASE64"));
  const logoB64 = process.env.PASS_LOGO_PNG_BASE64;
  const logoPng = logoB64 ? b64ToBuffer(logoB64) : null;

  // --- manifest.json ---
  const manifest: Record<string, string> = {
    "pass.json": sha1Hex(passJsonBuf),
    "icon.png": sha1Hex(iconPng),
  };
  if (logoPng) manifest["logo.png"] = sha1Hex(logoPng);

  const manifestBuf = Buffer.from(JSON.stringify(manifest, null, 2), "utf8");

  // --- signature (DER PKCS#7 detached) ---
  const signatureBuf = signManifestDer(manifestBuf);

  // --- zip (.pkpass) ---
  const zip = new JSZip();
  zip.file("pass.json", passJsonBuf);
  zip.file("icon.png", iconPng);
  if (logoPng) zip.file("logo.png", logoPng);
  zip.file("manifest.json", manifestBuf);
  zip.file("signature", signatureBuf);

  const pkpass = await zip.generateAsync({ type: "uint8array", compression: "DEFLATE" });

  // Uint8Array -> ArrayBuffer (BodyInit-safe)
  const pkpassArrayBuffer = new ArrayBuffer(pkpass.byteLength);
  new Uint8Array(pkpassArrayBuffer).set(pkpass);

  return new Response(pkpassArrayBuffer, {
    status: 200,
    headers: {
      "Content-Type": "application/vnd.apple.pkpass",
      "Content-Disposition": `attachment; filename="casa-marana-${serial}.pkpass"`,
      "Cache-Control": "no-store",
    },
  });
}

// GET: query string params
export async function GET(req: Request) {
  const body = parseGetBody(req);
  return generatePkpass(req, body);
}

// POST: JSON body
export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as RequestBody;
  return generatePkpass(req, body);
}
