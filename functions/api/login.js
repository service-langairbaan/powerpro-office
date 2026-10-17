
const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function verifyPassword(password, storedHash) {
  // Format: pbkdf2_sha256$iterations$salt$hash
  const parts = storedHash.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") {
    return false;
  }

  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) ||
      iterations < 100000 || iterations > 1000000) {
    return false;
  }

  const decode = (value) => {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(normalized);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
  };

  try {
    const salt = decode(parts[2]);
    const expected = decode(parts[3]);
    if (salt.length < 16 || expected.length !== 32) return false;

    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
    );

    const actual = new Uint8Array(
      await crypto.subtle.deriveBits({
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      }, key, 256)
    );

    let difference = 0;
    for (let i = 0; i < 32; i++) {
      difference |= actual[i] ^ expected[i];
    }
    return difference === 0;
  } catch {
    return false;
  }
}

async function signSession(payload, secret) {
  const body = base64url(
    encoder.encode(JSON.stringify(payload))
  );

  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );

  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, encoder.encode(body))
  );

  return `${body}.${base64url(signature)}`;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB || !env.SESSION_SECRET ||
        env.SESSION_SECRET.length < 32) {
      return json({ error: "Server configuration error" }, 503);
    }

    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) {
      return json({ error: "Forbidden" }, 403);
    }

    if (!(request.headers.get("Content-Type") || "")
        .toLowerCase().startsWith("application/json")) {
      return json({ error: "JSON required" }, 415);
    }

    const { email, password } = await request.json();

    if (typeof email !== "string" ||
        typeof password !== "string" ||
        email.length > 254 || password.length > 1024) {
      return json({ error: "Invalid request" }, 400);
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await env.DB.prepare(
      `SELECT id, email, password_hash, role, is_active
       FROM admin_users
       WHERE email = ? LIMIT 1`
    ).bind(normalizedEmail).first();

    const valid = user && user.is_active === 1 &&
      await verifyPassword(password, user.password_hash);

    if (!valid) {
      return json({
        error: "อีเมลหรือรหัสผ่านไม่ถูกต้อง"
      }, 401);
    }

    const now = Math.floor(Date.now() / 1000);
    const token = await signSession({
      sub: String(user.id),
      role: user.role,
      iat: now,
      exp: now + 8 * 60 * 60
    }, env.SESSION_SECRET);

    return json({
      success: true,
      user: {
        email: user.email,
        role: user.role
      }
    }, 200, {
      "Set-Cookie":
        `pp_session=${token}; HttpOnly; Secure; ` +
        `SameSite=Strict; Path=/; Max-Age=28800`
    });

  } catch (error) {
    console.error("Login error:", error);
    return json({ error: "Unable to sign in" }, 500);
  }
}
