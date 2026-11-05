
export async function onRequestGet({ request, env }) {
  if (!env.GITHUB_CLIENT_ID) {
    return new Response("OAuth is not configured.", {
      status: 500
    });
  }

  const url = new URL(request.url);

  // Generate a cryptographically secure state value
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);

  const state = Array.from(randomBytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  // Store state in a secure, temporary cookie
  const cookie = [
    `oauth_state=${state}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/api/auth",
    "Max-Age=600"
  ].join("; ");

  // Redirect to GitHub OAuth authorization
  const github = new URL(
    "https://github.com/login/oauth/authorize"
  );

  github.searchParams.set(
    "client_id",
    env.GITHUB_CLIENT_ID
  );

  github.searchParams.set(
    "redirect_uri",
    `${url.origin}/api/auth/callback`
  );

  github.searchParams.set("state", state);

  // Request only basic public identity information
  github.searchParams.set("scope", "");

  return new Response(null, {
    status: 302,
    headers: {
      "Location": github.toString(),
      "Set-Cookie": cookie,
      "Cache-Control": "no-store"
    }
  });
}
