import twilio from "twilio";

export async function POST(req: Request) {
  const expected = (process.env.CASA_APP_API_KEY || "").trim();
  const got = (req.headers.get("x-api-key") || "").trim();

  if (!expected || got !== expected) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
  }

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
  } catch (err: any) {
    return new Response(
      JSON.stringify({ error: err?.message ?? "Failed to send verification code" }),
      { status: 400 }
    );
  }
}
