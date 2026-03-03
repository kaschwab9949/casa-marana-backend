import twilio from "twilio";
import { requireApiKey } from "@/lib/auth";

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

export async function POST(req: Request) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const serviceSid = process.env.TWILIO_VERIFY_SERVICE_SID;

  if (!accountSid || !authToken || !serviceSid) {
    return new Response(JSON.stringify({ error: "Missing Twilio environment variables" }), { status: 500 });
  }

  const body = await req.json().catch(() => ({}));
  const phone = (body.phone as string | undefined)?.trim();

  if (!phone || !phone.startsWith("+")) {
    return new Response(JSON.stringify({ error: "Invalid phone number" }), { status: 400 });
  }

  try {
    const client = twilio(accountSid, authToken);
    const verification = await client.verify.v2
      .services(serviceSid)
      .verifications.create({ to: phone, channel: "sms" });

    return new Response(JSON.stringify({ requestId: verification.sid }), { status: 200 });
  } catch (err: unknown) {
    return new Response(
      JSON.stringify({ error: errorMessage(err) || "Failed to send verification code" }),
      { status: 400 }
    );
  }
}
