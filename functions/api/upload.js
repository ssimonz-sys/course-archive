
const REPO_OWNER = "ssimonz-sys";
const REPO_NAME = "course-archive";
const MAX_FILE_SIZE = 8 * 1024 * 1024;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function fromBase64Url(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const binary = atob(normalized);

  return Uint8Array.from(
    binary,
    char => char.charCodeAt(0)
  );
}

async function verifyAdmin(request, env) {
  if (!env.SESSION_SECRET || !env.ADMIN_GITHUB_ID) {
    return false;
  }

  const cookies = request.headers.get("Cookie") || "";

  const session = cookies
    .split(";")
    .map(item => item.trim())
    .find(item => item.startsWith("course_archive_session="));

  if (!session) return false;

  try {
    const token = session.split("=").slice(1).join("=");
    const parts = token.split(".");

    if (parts.length !== 2) return false;

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

    if (!valid) return false;

    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64Url(body))
    );

    return (
      Number.isSafeInteger(payload.exp) &&
      payload.exp > Math.floor(Date.now() / 1000) &&
      String(payload.id) === String(env.ADMIN_GITHUB_ID)
    );
  } catch {
    return false;
  }
}

function cleanText(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");
}

function safeFilename(value) {
  return value
    .replace(/[\/\\:*?"<>|]/g, "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .replace(/\s+/g, " ")
    .replace(/^\.+/, "")
    .replace(/[. ]+$/, "")
    .trim();
}

function bytesToBase64(bytes) {
  const chunkSize = 8192;
  let binary = "";

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);

    for (const byte of chunk) {
      binary += String.fromCharCode(byte);
    }
  }

  return btoa(binary);
}

export async function onRequestPost({ request, env }) {
  const origin = new URL(request.url).origin;

  // Protect against cross-site upload requests.
  if (request.headers.get("Origin") !== origin) {
    return json({ error: "Invalid request origin." }, 403);
  }

  // Verify the signed administrator session.
  if (!(await verifyAdmin(request, env))) {
    return json({
      error: "Unauthorized. Please sign in again."
    }, 401);
  }

  if (!env.GITHUB_UPLOAD_TOKEN) {
    return json({
      error: "GitHub upload token is not configured."
    }, 500);
  }

  // Limit request size before parsing.
  const contentLength = Number(
    request.headers.get("Content-Length")
  );

  if (
    Number.isFinite(contentLength) &&
    contentLength > MAX_FILE_SIZE + 65536
  ) {
    return json({
      error: "PDF must be smaller than 8 MB."
    }, 413);
  }

  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().startsWith("multipart/form-data")) {
    return json({ error: "Invalid upload format." }, 400);
  }

  let form;

  try {
    form = await request.formData();
  } catch {
    return json({ error: "Unable to read upload." }, 400);
  }

  const course = cleanText(form.get("course"));
  const title = cleanText(form.get("title"));
  const file = form.get("file");

  const match = course.match(/^([A-Za-z]{2,6})\s*(\d{3,4})$/);

  if (!match) {
    return json({
      error: "Course code must look like BIOL 230 or MICB 306."
    }, 400);
  }

  if (!title || title.length > 120) {
    return json({
      error: "Document title must contain 1 to 120 characters."
    }, 400);
  }

  if (!(file instanceof File)) {
    return json({ error: "Please select a PDF." }, 400);
  }

  if (file.size === 0 || file.size > MAX_FILE_SIZE) {
    return json({
      error: "PDF must be between 1 byte and 8 MB."
    }, 413);
  }

  if (!file.name.toLowerCase().endsWith(".pdf")) {
    return json({ error: "Only PDF files are allowed." }, 400);
  }

  const bytes = new Uint8Array(await file.arrayBuffer());

  // Check the PDF file signature.
  const signature = new TextDecoder().decode(bytes.slice(0, 5));

  if (signature !== "%PDF-") {
    return json({
      error: "The selected file is not a valid PDF header."
    }, 400);
  }

  const courseCode = `${match[1].toUpperCase()} ${match[2]}`;
  const documentTitle = safeFilename(title);

  if (!documentTitle) {
    return json({ error: "Invalid document title." }, 400);
  }

  // Keep filenames compatible with the existing homepage.
  const filename = `${courseCode} ${documentTitle}.pdf`;
  const path = `files/${filename}`;

  const encodedPath = path
    .split("/")
    .map(encodeURIComponent)
    .join("/");

  const githubUrl =
    `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}` +
    `/contents/${encodedPath}`;

  const headers = {
    "Authorization": `Bearer ${env.GITHUB_UPLOAD_TOKEN}`,
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "CourseArchiveUploader"
  };

  try {
    // Prevent accidental overwriting.
    const existing = await fetch(githubUrl, {
      method: "GET",
      headers
    });

    if (existing.ok) {
      return json({
        error: "A document with this name already exists."
      }, 409);
    }

    if (existing.status !== 404) {
      return json({
        error: "Unable to check existing files."
      }, 502);
    }

    // Commit the PDF to the GitHub repository.
    const response = await fetch(githubUrl, {
      method: "PUT",
      headers: {
        ...headers,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: `Upload ${filename}`,
        content: bytesToBase64(bytes),
        branch: "main"
      })
    });

    if (response.status === 409 || response.status === 422) {
      return json({
        error: "GitHub rejected the upload. The file may already exist."
      }, 409);
    }

    if (!response.ok) {
      return json({
        error: "GitHub upload failed.",
        status: response.status
      }, 502);
    }

    return json({
      success: true,
      filename,
      path,
      message: "PDF uploaded. Website deployment is pending."
    }, 201);

  } catch {
    return json({
      error: "Unable to connect to GitHub."
    }, 502);
  }
}
