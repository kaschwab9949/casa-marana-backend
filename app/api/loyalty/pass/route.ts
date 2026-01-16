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

type Tier = { id: string; level: number; name: string; minPoints: number };

// MUST match your Xcode membershipTiers (name + minPoints)
const TIERS: Tier[] = [
  { id: "starter", level: 1, name: "Starter", minPoints: 0 },
  { id: "community", level: 2, name: "Community", minPoints: 100 },
  { id: "friend", level: 3, name: "Friend", minPoints: 500 },
  { id: "family", level: 4, name: "Family", minPoints: 1000 },
  { id: "inner", level: 5, name: "The Inner Circle", minPoints: 4000 }
];

function mustEnv(name: string): string {
  const v = process.env[name];
  if (!v || !v.trim()) throw new Error(`Missing env var: ${name}`);
  return v.trim();
}

function normalizeE164(phone: string): string {
  const p = phone.trim();
  if (!p.startsWith("+")) throw new Error("phone must be E.164 and start with + (example: +15201234567)");
  return p;
}

function tierForPoints(points: number): Tier {
  const sorted = [...TIERS].sort((a, b) => a.minPoints - b.minPoints);
  return sorted.filter(t => t.minPoints <= points).slice(-1)[0] ?? sorted[0];
}

function sha1Hex(buf: Buffer): string {
  return crypto.createHash("sha1").update(buf).digest("hex");
}

function squareBaseUrl(): string {
  const env = (process.env.SQUARE_ENV || "production").toLowerCase();
  return env === "sandbox" ? "https://connect.squareupsandbox.com" : "https://connect.squareup.com";
}

async function squareFetch<T>(endpoint: string, method: "GET" | "POST", body?: any): Promise<T> {
  const token = mustEnv("SQUARE_ACCESS_TOKEN");
  const version = (process.env.SQUARE_VERSION || "2024-01-18").trim();

  const res = await fetch(`${squareBaseUrl()}${endpoint}`, {
    method,
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
      "Square-Version": version
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch {}

  if (!res.ok) {
    const msg =
      json?.errors?.[0]?.detail ||
      json?.errors?.[0]?.code ||
      json?.message ||
      text ||
      `Square error ${res.status}`;
    throw new Error(msg);
  }

  return json as T;
}

async function getSquareCustomerByPhone(phoneE164: string): Promise<{ id: string; name: string }> {
  // /v2/customers/search
  const payload = {
    query: { filter: { phoneNumber: { exact: phoneE164 } } },
    limit: 1
  };

  const data = await squareFetch<{ customers?: any[] }>("/v2/customers/search", "POST", payload);
  const c = data.customers?.[0];
  if (!c) throw new Error("No Square customer found for this phone number.");

  const name =
    [c.given_name, c.family_name].filter(Boolean).join(" ").trim() ||
    c.company_name ||
    "Member";

  return { id: c.id, name };
}

async function getLoyaltyPointsByPhone(phoneE164: string): Promise<number> {
  // /v2/loyalty/accounts/search
  const payload = {
    query: { mappings: [{ phone_number: phoneE164 }] },
    limit: 1
  };

  const data = await squareFetch<{ loyalty_accounts?: any[] }>("/v2/loyalty/accounts/search", "POST", payload);
  const acct = data.loyalty_accounts?.[0];
  if (!acct) throw new Error("No Square Loyalty account found for this phone number.");

  const balance = Number(acct.balance ?? 0);
  return Number.isFinite(balance) ? balance : 0;
}

function readAsset(rel: string): Buffer {
  // These must exist in your repo:
  // app/api/loyalty/pass/assets/WWDR.pem
  // app/api/loyalty/pass/assets/icon.png
  const p = path.join(process.cwd(), "app", "api", "loyalty", "pass", "assets", rel);
  return fs.readFileSync(p);
}

async function extractPemFromP12(tmpDir: string) {
  const p12b64 = mustEnv("PASS_P12_BASE64");
  const p12Password = mustEnv("PASS_P12_PASSWORD");

  const p12Path = path.join(tmpDir, "pass.p12");
  fs.writeFileSync(p12Path, Buffer.from(p12b64, "base64"));

  const signerCertPemPath = path.join(tmpDir, "signerCert.pem");
  const signerKeyPemPath = path.join(tmpDir, "signerKey.pem");

  // Extract signer cert
  await execFileAsync("openssl", [
    "pkcs12",
    "-in", p12Path,
    "-clcerts",
    "-nokeys",
    "-out", signerCertPemPath,
    "-passin", `pass:${p12Password}`
  ]);

  // Extract signer key (encrypted; uses same passphrase for simplicity)
  await execFileAsync("openssl", [
    "pkcs12",
    "-in", p12Path,
    "-nocerts",
    "-out", signerKeyPemPath,
    "-passin", `pass:${p12Password}`,
    "-passout", `pass:${p12Password}`
  ]);

  return { signerCertPemPath, signerKeyPemPath, signerKeyPassphrase: p12Password };
}

async function signManifestWithOpenSSL(args: {
  manifestPath: string;
  signaturePath: string;
  signerCertPemPath: string;
  signerKeyPemPath: string;
  signerKeyPassphrase: string;
  wwdrPemPath: string;
}) {
  // openssl smime -binary -sign -signer ... -inkey ... -certfile ... -in manifest.json -out signature -outform DER
  await execFileAsync("openssl", [
    "smime",
    "-binary",
    "-sign",
    "-signer", args.signerCertPemPath,
    "-inkey", args.signerKeyPemPath,
    "-passin", `pass:${args.signerKeyPassphrase}`,
    "-certfile", args.wwdrPemPath,
    "-in", args.manifestPath,
    "-out", args.signaturePath,
    "-outform", "DER"
  ]);
}

export async function GET(req: Request) {
  try {
    const url = new URL(req.url);
    const phone = url.searchParams.get("phone");
    if (!phone) return new Response("Missing phone", { status: 400 });

    const phoneE164 = normalizeE164(phone);

    // 1) Pull Square identity + points
    const customer = await getSquareCustomerByPhone(phoneE164);
    const points = await getLoyaltyPointsByPhone(phoneE164);

    // 2) Compute tier (matches your Xcode tiers)
    const tier = tierForPoints(points);

    // 3) Pass identifiers
    const passTypeId = mustEnv("PASS_TYPE_ID");     // pass.com.casamarana.loyalty
    const teamId = mustEnv("APPLE_TEAM_ID");        // Y32NA77D5W

    // Stable unique serial without storing DB
    const serial = `cm-${crypto.createHash("sha1").update(phoneE164).digest("hex").slice(0, 16)}`;

    // 4) Build pass.json (NAME + TIER only)
    const passJson = {
      formatVersion: 1,
      passTypeIdentifier: passTypeId,
      teamIdentifier: teamId,
      organizationName: "Casa Marana",
      description: "Casa Marana Membership",
      serialNumber: serial,
      backgroundColor: "rgb(20,20,20)",
      foregroundColor: "rgb(255,255,255)",
      labelColor: "rgb(200,200,200)",
      storeCard: {
        primaryFields: [{ key: "tier", label: "Tier", value: tier.name }],
        secondaryFields: [{ key: "name", label: "Member", value: customer.name }]
      }
    };

    const passJsonBuf = Buffer.from(JSON.stringify(passJson, null, 2), "utf8");

    // 5) Required files
    const iconPng = readAsset("icon.png");
    const wwdrPem = readAsset("WWDR.pem");

    // 6) manifest.json (SHA-1 hashes)
    const manifestObj: Record<string, string> = {
      "pass.json": sha1Hex(passJsonBuf),
      "icon.png": sha1Hex(iconPng)
    };
    const manifestBuf = Buffer.from(JSON.stringify(manifestObj, null, 2), "utf8");

    // 7) Sign manifest.json -> signature
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-pass-"));
    try {
      const wwdrPemPath = path.join(tmpDir, "WWDR.pem");
      fs.writeFileSync(wwdrPemPath, wwdrPem);

      const { signerCertPemPath, signerKeyPemPath, signerKeyPassphrase } = await extractPemFromP12(tmpDir);

      const manifestPath = path.join(tmpDir, "manifest.json");
      const signaturePath = path.join(tmpDir, "signature");
      fs.writeFileSync(manifestPath, manifestBuf);

      await signManifestWithOpenSSL({
        manifestPath,
        signaturePath,
        signerCertPemPath,
        signerKeyPemPath,
        signerKeyPassphrase,
        wwdrPemPath
      });

      const signatureBuf = fs.readFileSync(signaturePath);

      // 8) Zip into .pkpass
      const zip = new JSZip();
      zip.file("pass.json", passJsonBuf);
      zip.file("icon.png", iconPng);
      zip.file("manifest.json", manifestBuf);
      zip.file("signature", signatureBuf);

const pkpass = await zip.generateAsync({ type: "uint8array", compression: "DEFLATE" });
      
return new Response(new Blob([pkpass], { type: "application/vnd.apple.pkpass" }), {
  status: 200,
        headers: {
          "Content-Type": "application/vnd.apple.pkpass",
          "Content-Disposition": `attachment; filename="casa-marana-${serial}.pkpass"`,
          "Cache-Control": "no-store"
        }
      });
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  } catch (e: any) {
    return new Response(e?.message || "Unknown error", { status: 500 });
  }
}
