
const encoder = new TextEncoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function base64url(bytes) {
  let str = "";
  for (const byte of bytes) str += String.fromCharCode(byte);
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 310000;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const hash = new Uint8Array(
    await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    }, key, 256)
  );

  return `pbkdf2_sha256$${iterations}$${base64url(salt)}$${base64url(hash)}`;
}

function safeEqual(a, b) {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  let diff = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);

  for (let i = 0; i < length; i++) {
    diff |= (aa[i] || 0) ^ (bb[i] || 0);
  }
  return diff === 0;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB || !env.ADMIN_SETUP_SECRET ||
        env.ADMIN_SETUP_SECRET.length < 32) {
      return json({ error: "Configuration error" }, 503);
    }

    const origin = request.headers.get("Origin");
    if (origin !== new URL(request.url).origin) {
      return json({ error: "Forbidden" }, 403);
    }

    if (!(request.headers.get("Content-Type") || "")
      .toLowerCase().startsWith("application/json")) {
      return json({ error: "JSON required" }, 415);
    }

    const body = await request.json();
    const { setupSecret, password } = body;

    if (typeof setupSecret !== "string" ||
        typeof password !== "string" ||
        !safeEqual(setupSecret, env.ADMIN_SETUP_SECRET)) {
      return json({ error: "Unauthorized" }, 401);
    }

    if (password.length < 12 || password.length > 128) {
      return json({ error: "Password must be 12-128 characters" }, 400);
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM admin_users LIMIT 1"
    ).first();

    if (existing) {
      return json({ error: "Admin already initialized" }, 409);
    }

    const email = "info.service@langairbaan.com";
    const passwordHash = await hashPassword(password);

    await env.DB.prepare(
      `INSERT INTO admin_users
       (email, password_hash, role, is_active)
       VALUES (?, ?, 'admin', 1)`
    ).bind(email, passwordHash).run();

    return json({
      success: true,
      message: "Admin account created",
      email
    }, 201);

  } catch (error) {
    console.error("Setup error:", error);
    return json({ error: "Setup failed" }, 500);
  }
}
