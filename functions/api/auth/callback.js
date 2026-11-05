
const COOKIE_NAME = "course_archive_session";

function redirect(url, cookie) {
  const headers = { Location: url, "Cache-Control": "no-store" };
  if (cookie) headers["Set-Cookie"] = cookie;
  return new Response(null, { status: 302, headers });
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function signSession(payload, secret) {
  const encoder = new TextEncoder();
  const body = toBase64Url(encoder.encode(JSON.stringify(payload)));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(body)
  );

  return `${body}.${toBase64Url(new Uint8Array(signature))}`;
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const origin = url.origin;
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = Object.fromEntries(
    cookieHeader.split(";").map(part => {
      const index = part.indexOf("=");
      return index < 0
        ? [part.trim(), ""]
        : [part.slice(0, index).trim(), part.slice(index + 1).trim()];
    })
  );

  const clearState =
    "oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";

  if (!code || !state || !cookies.oauth_state ||
      state !== cookies.oauth_state) {
    return redirect("/admin.html?error=invalid_state", clearState);
  }

  const {
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    SESSION_SECRET,
    ADMIN_GITHUB_ID
  } = env;

  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET ||
      !SESSION_SECRET || !ADMIN_GITHUB_ID) {
    return new Response("OAuth configuration missing", { status: 500 });
  }

  const tokenResponse = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${origin}/api/auth/callback`
      })
    }
  );

  if (!tokenResponse.ok) {
    return redirect("/admin.html?error=token_exchange", clearState);
  }

  const tokenData = await tokenResponse.json();

  if (!tokenData.access_token) {
    return redirect("/admin.html?error=token_exchange", clearState);
  }

  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      "Authorization": `Bearer ${tokenData.access_token}`,
      "Accept": "application/vnd.github+json",
      "User-Agent": "CourseArchive"
    }
  });

  if (!userResponse.ok) {
    return redirect("/admin.html?error=github_user", clearState);
  }

  const user = await userResponse.json();

  if (String(user.id) !== String(ADMIN_GITHUB_ID)) {
    return redirect("/admin.html?error=unauthorized", clearState);
  }

  const session = await signSession({
    id: user.id,
    login: user.login,
    exp: Math.floor(Date.now() / 1000) + 86400
  }, SESSION_SECRET);

  const sessionCookie =
    `${COOKIE_NAME}=${session}; Path=/; HttpOnly; Secure; ` +
    "SameSite=Lax; Max-Age=86400";

  const headers = new Headers({
    Location: "/admin.html?login=success",
    "Cache-Control": "no-store"
  });

  headers.append("Set-Cookie", clearState);
  headers.append("Set-Cookie", sessionCookie);

  return new Response(null, { status: 302, headers });
}
