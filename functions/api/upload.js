
const REPO_OWNER = "ssimonz-sys";
const REPO_NAME = "course-archive";
const MAX_FILE_SIZE = 8 * 1024 * 1024;

const ALLOWED = new Set([
  "pdf", "jpg", "jpeg", "png",
  "webp", "heic", "docx", "ipynb"
]);

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
    .find(item =>
      item.startsWith("course_archive_session=")
    );

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

function base64Size(base64) {
  const padding = base64.endsWith("==")
    ? 2
    : base64.endsWith("=")
      ? 1
      : 0;

  return base64.length * 3 / 4 - padding;
}

function base64Prefix(base64, count = 32) {
  const length = Math.ceil(count / 3) * 4;
  const decoded = atob(base64.slice(0, length));

  return Uint8Array.from(
    decoded,
    char => char.charCodeAt(0)
  );
}

function matchesSignature(bytes, extension) {
  const starts = (...signature) =>
    signature.every(
      (value, index) => bytes[index] === value
    );

  const ascii = (start, end) =>
    String.fromCharCode(...bytes.slice(start, end));

  if (extension === "pdf") {
    return starts(
      0x25, 0x50, 0x44, 0x46, 0x2d
    );
  }

  if (
    extension === "jpg" ||
    extension === "jpeg"
  ) {
    return starts(0xff, 0xd8, 0xff);
  }

  if (extension === "png") {
    return starts(
      0x89, 0x50, 0x4e, 0x47,
      0x0d, 0x0a, 0x1a, 0x0a
    );
  }

  if (extension === "webp") {
    return (
      ascii(0, 4) === "RIFF" &&
      ascii(8, 12) === "WEBP"
    );
  }

  if (extension === "heic") {
    return (
      ascii(4, 8) === "ftyp" &&
      [
        "heic", "heix", "hevc",
        "hevx", "mif1", "msf1"
      ].includes(ascii(8, 12))
    );
  }

  if (extension === "docx") {
    return starts(
      0x50, 0x4b, 0x03, 0x04
    );
  }

  if (extension === "ipynb") {
    // Full notebook validation is performed
    // in the browser before encoding.
    return true;
  }

  return false;
}

export async function onRequestPost({ request, env }) {
  const origin = new URL(request.url).origin;

  if (request.headers.get("Origin") !== origin) {
    return json({
      error: "Invalid request origin."
    }, 403);
  }

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

  const contentType =
    request.headers.get("Content-Type") || "";

  if (
    !contentType.toLowerCase()
      .startsWith("application/json")
  ) {
    return json({
      error: "Invalid upload format."
    }, 400);
  }

  // Base64 expands binary data by approximately 33%.
  const MAX_REQUEST_SIZE =
    Math.ceil(MAX_FILE_SIZE * 4 / 3) + 16384;

  const lengthHeader =
    request.headers.get("Content-Length");

  if (
    lengthHeader !== null &&
    Number(lengthHeader) > MAX_REQUEST_SIZE
  ) {
    return json({
      error: "Upload exceeds the 8 MB file limit."
    }, 413);
  }

  let rawBody;

  try {
    rawBody = await request.text();
  } catch {
    return json({
      error: "Unable to read upload."
    }, 400);
  }

  if (rawBody.length > MAX_REQUEST_SIZE) {
    return json({
      error: "Upload exceeds the 8 MB file limit."
    }, 413);
  }

  let data;

  try {
    data = JSON.parse(rawBody);
  } catch {
    return json({
      error: "Invalid JSON upload."
    }, 400);
  }

  const course = cleanText(data.course);
  const title = cleanText(data.title);
  const originalName = String(data.filename || "");
  const content = data.content;

  const match = course.match(
    /^([A-Za-z]{2,6})\s*(\d{3,4})$/
  );

  if (!match) {
    return json({
      error:
        "Course code must look like BIOL 230 or MICB 306."
    }, 400);
  }

  if (!title || title.length > 120) {
    return json({
      error:
        "Document title must contain 1 to 120 characters."
    }, 400);
  }

  const extension = originalName
    .split(".")
    .pop()
    .toLowerCase();

  if (!ALLOWED.has(extension)) {
    return json({
      error: "Unsupported file type."
    }, 400);
  }

  if (
    typeof content !== "string" ||
    content.length === 0 ||
    content.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(content)
  ) {
    return json({
      error: "Invalid Base64 file content."
    }, 400);
  }

  const fileSize = base64Size(content);

  if (
    !Number.isInteger(fileSize) ||
    fileSize <= 0 ||
    fileSize > MAX_FILE_SIZE
  ) {
    return json({
      error: "File must be between 1 byte and 8 MB."
    }, 413);
  }

  let prefix;

  try {
    prefix = base64Prefix(content);
  } catch {
    return json({
      error: "Unable to validate file content."
    }, 400);
  }

  if (!matchesSignature(prefix, extension)) {
    return json({
      error:
        "File contents do not match the selected format."
    }, 400);
  }

  const courseCode =
    `${match[1].toUpperCase()} ${match[2]}`;

  const documentTitle = safeFilename(title);

  if (!documentTitle) {
    return json({
      error: "Invalid document title."
    }, 400);
  }

  const filename =
    `${courseCode} ${documentTitle}.${extension}`;

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

    const response = await fetch(githubUrl, {
      method: "PUT",
      headers: {
        ...headers,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: `Upload ${filename}`,
        content,
        branch: "main"
      })
    });

    if (
      response.status === 409 ||
      response.status === 422
    ) {
      return json({
        error:
          "GitHub rejected the upload. The file may already exist."
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
      message:
        "File uploaded. Website deployment is pending."
    }, 201);

  } catch {
    return json({
      error: "Unable to connect to GitHub."
    }, 502);
  }
}
