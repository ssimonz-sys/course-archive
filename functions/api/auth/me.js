
const COOKIE_NAME = "course_archive_session";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function fromBase64Url(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const binary = atob(normalized);

  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

export async function onRequestGet({ request, env }) {
  if (!env.SESSION_SECRET || !env.ADMIN_GITHUB_ID) {
    return json({ error: "Server configuration missing" }, 500);
  }

  const cookieHeader = request.headers.get("Cookie") || "";

  const sessionCookie = cookieHeader
    .split(";")
    .map(part => part.trim())
    .find(part => part.startsWith(`${COOKIE_NAME}=`));

  if (!sessionCookie) {
    return json({ authenticated: false }, 401);
  }

  try {
    const token = sessionCookie.slice(COOKIE_NAME.length + 1);
    const parts = token.split(".");

    if (parts.length !== 2) {
      return json({ authenticated: false }, 401);
    }

    const [body, signature] = parts;
    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(env.SESSION_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      fromBase64Url(signature),
      encoder.encode(body)
    );

    if (!valid) {
      return json({ authenticated: false }, 401);
    }

    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64Url(body))
    );

    const now = Math.floor(Date.now() / 1000);

    if (
      !Number.isSafeInteger(payload.exp) ||
      payload.exp <= now ||
      String(payload.id) !== String(env.ADMIN_GITHUB_ID)
    ) {
      return json({ authenticated: false }, 401);
    }

    return json({
      authenticated: true,
      user: {
        id: payload.id,
        login: payload.login
      }
    });

  } catch {
    return json({ authenticated: false }, 401);
  }
}
