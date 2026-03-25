const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const os = require("os");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { JSONFilePreset } = require("lowdb/node");
const { nanoid } = require("nanoid");
const { PrismaClient } = require("@prisma/client");

const {
  S3Client,
  PutObjectCommand,
  ListObjectsV2Command,
  GetObjectCommand,
} = require("@aws-sdk/client-s3");

dotenv.config();

const app = express();

const prisma = process.env.DATABASE_URL ? new PrismaClient() : null;

const PORT = Number(process.env.PORT || 8000);
const CORS_ORIGIN_RAW = process.env.CORS_ORIGIN || "http://localhost:5173";
const CORS_ORIGINS = CORS_ORIGIN_RAW
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  // eslint-disable-next-line no-console
  console.warn("Missing JWT_SECRET in backend/.env");
}

const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;
const APP_PASSWORD_HASH = process.env.APP_PASSWORD_HASH;
if (!APP_USERNAME || (!APP_PASSWORD && !APP_PASSWORD_HASH)) {
  console.warn(
    "Missing APP_USERNAME and/or APP_PASSWORD/APP_PASSWORD_HASH in backend/.env",
  );
}

// --- Middleware
app.use(
  cors({
    origin: function (origin, callback) {
      // Allow non-browser requests (like curl) where `origin` can be undefined.
      if (!origin) return callback(null, true);

      // If you set CORS_ORIGIN="*" then allow everything (useful for testing).
      if (CORS_ORIGINS.includes("*")) return callback(null, true);

      if (CORS_ORIGINS.includes(origin)) return callback(null, true);

      // Block unknown origins without throwing.
      return callback(null, false);
    },
    credentials: false,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type", "Accept", "X-Requested-With"],
  }),
);



app.use(express.json({ limit: "1mb" }));

app.get("/healthz", (req, res) => res.json({ ok: true }));

function authRequired(req, res, next) {
  const header = req.headers.authorization;
  const token =
    header && header.startsWith("Bearer ")
      ? header.slice("Bearer ".length)
      : null;
  if (!token) return res.status(401).json({ message: "Missing token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { username: decoded.sub };
    return next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid/expired token" });
  }
}

// --- Auth routes
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "username and password are required" });
  }

  if (username !== APP_USERNAME) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  try {
    let ok = false;
    if (APP_PASSWORD_HASH) {
      ok = await bcrypt.compare(password, APP_PASSWORD_HASH);
    } else if (APP_PASSWORD) {
      ok = password === APP_PASSWORD;
    }

    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ sub: APP_USERNAME }, JWT_SECRET, {
      expiresIn: "7d",
    });
    return res.json({ token, user: { username: APP_USERNAME } });
  } catch (e) {
    return res.status(500).json({ message: "Login failed" });
  }
});

app.get("/api/auth/me", authRequired, (req, res) => {
  return res.json({ user: { username: req.user.username } });
});

// --- Tasks (simple JSON "database")
// Stored locally in backend/.data/tasks.json by default.
const TASKS_DB_PATH =
  process.env.TASKS_DB_PATH ||
  path.join(__dirname, ".data", "tasks.json");

async function getTasksDb() {
  const dir = path.dirname(TASKS_DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const db = await JSONFilePreset(TASKS_DB_PATH, { tasks: [] });
  return db;
}

function normalizeTaskStatus(status) {
  const s = String(status || "").toLowerCase();
  if (s === "todo" || s === "in_progress" || s === "done") return s;
  return "todo";
}

app.get("/api/tasks", authRequired, async (req, res) => {
  try {
    if (prisma) {
      const tasks = await prisma.task.findMany({
        orderBy: { createdAt: "desc" },
      });
      return res.json({ ok: true, tasks });
    }

    const db = await getTasksDb();
    const tasks = Array.isArray(db.data.tasks) ? db.data.tasks : [];
    return res.json({ ok: true, tasks });
  } catch (e) {
    return res.status(500).json({ ok: false, message: "Failed to load tasks", error: e?.message });
  }
});

app.post("/api/tasks", authRequired, async (req, res) => {
  const { title, description, status } = req.body || {};
  if (!title || !String(title).trim()) {
    return res.status(400).json({ ok: false, message: "title is required" });
  }

  const task = {
    id: nanoid(10),
    title: String(title).trim(),
    description: description ? String(description).trim() : "",
    status: normalizeTaskStatus(status),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  try {
    if (prisma) {
      const created = await prisma.task.create({
        data: {
          id: task.id,
          title: task.title,
          description: task.description,
          status: task.status,
        },
      });
      return res.json({ ok: true, task: created });
    }

    const db = await getTasksDb();
    db.data.tasks.push(task);
    await db.write();
    return res.json({ ok: true, task });
  } catch (e) {
    return res.status(500).json({ ok: false, message: "Failed to create task", error: e?.message });
  }
});

app.patch("/api/tasks/:id", authRequired, async (req, res) => {
  const { id } = req.params;
  const { title, description, status } = req.body || {};

  try {
    if (prisma) {
      const updated = await prisma.task.update({
        where: { id },
        data: {
          ...(title !== undefined ? { title: String(title).trim() } : {}),
          ...(description !== undefined ? { description: String(description).trim() } : {}),
          ...(status !== undefined ? { status: normalizeTaskStatus(status) } : {}),
        },
      });
      return res.json({ ok: true, task: updated });
    }

    const db = await getTasksDb();
    const tasks = Array.isArray(db.data.tasks) ? db.data.tasks : [];
    const idx = tasks.findIndex((t) => t.id === id);
    if (idx === -1) return res.status(404).json({ ok: false, message: "not found" });

    const prev = tasks[idx];
    const next = {
      ...prev,
      title: title !== undefined ? String(title).trim() : prev.title,
      description:
        description !== undefined ? String(description).trim() : prev.description,
      status: status !== undefined ? normalizeTaskStatus(status) : prev.status,
      updatedAt: new Date().toISOString(),
    };
    tasks[idx] = next;
    db.data.tasks = tasks;
    await db.write();
    return res.json({ ok: true, task: next });
  } catch (e) {
    return res.status(500).json({ ok: false, message: "Failed to update task", error: e?.message });
  }
});

app.delete("/api/tasks/:id", authRequired, async (req, res) => {
  const { id } = req.params;
  try {
    if (prisma) {
      await prisma.task.delete({ where: { id } });
      return res.json({ ok: true });
    }

    const db = await getTasksDb();
    const tasks = Array.isArray(db.data.tasks) ? db.data.tasks : [];
    const next = tasks.filter((t) => t.id !== id);
    if (next.length === tasks.length) {
      return res.status(404).json({ ok: false, message: "not found" });
    }
    db.data.tasks = next;
    await db.write();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, message: "Failed to delete task", error: e?.message });
  }
});

// --- R2/S3 client
const {
  R2_ENDPOINT,
  R2_ACCESS_KEY_ID,
  R2_SECRET_ACCESS_KEY,
  R2_REGION,
  R2_BUCKET,
  R2_UPLOAD_PREFIX,
  MAX_FILES_PER_UPLOAD,
} = process.env;

if (!R2_ENDPOINT || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET) {
  console.warn("Missing Cloudflare R2 env vars in backend/.env");
}

const s3 = new S3Client({
  region: R2_REGION || "auto",
  endpoint: R2_ENDPOINT,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY,
  },
  forcePathStyle: true, // R2 needs path-style for some setups
});

function sanitizeSegment(seg) {
  const s = String(seg || "")
    .trim()
    .replace(/\\/g, "/")
    .replace(/^\/+/, "");
  if (!s || s === "." || s === "..") return "";
  // Keep it simple and safe for object keys.
  return s.replace(/[^a-zA-Z0-9._-]/g, "_");
}

function sanitizeRelativePath(input) {
  const normalized = String(input || "").replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  const safe = parts
    .map(sanitizeSegment)
    .filter(Boolean)
    // Prevent traversal-ish behavior if the browser sends odd paths.
    .filter((p) => p !== ".." && p !== ".");
  return safe.join("/");
}

// --- Multer upload
const tmpDir = path.join(__dirname, ".tmp");
if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir);

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, tmpDir);
  },
  filename: function (req, file, cb) {
    // Use a unique temp name; preserve original in `file.originalname`.
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const ext = path.extname(file.originalname || file.originalname || "");
    cb(null, `${unique}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: {
    files: Number(MAX_FILES_PER_UPLOAD || 200),
  },
});

app.post(
  "/api/upload",
  authRequired,
  upload.array("files"),
  async (req, res) => {
    const batchNameRaw = req.body?.batchName;
    // batchName is used as the destination prefix in R2.
    // Allow slashes so we can support nested folders like: uploads/team1/sub1
    const batchName =
      sanitizeRelativePath(batchNameRaw) || R2_UPLOAD_PREFIX || "uploads";

    const files = req.files || [];
    if (!files.length)
      return res.status(400).json({ message: "No files provided" });

    try {
      const uploaded = [];

      // Upload sequentially to reduce memory spikes.
      for (const file of files) {
        const relativePath = sanitizeRelativePath(file.originalname);
        if (!relativePath) continue;

        const key = `${batchName}/${relativePath}`;

        const bodyStream = fs.createReadStream(file.path);
        const contentType = file.mimetype || undefined;

        const command = new PutObjectCommand({
          Bucket: R2_BUCKET,
          Key: key,
          Body: bodyStream,
          ContentType: contentType,
        });

        await s3.send(command);
        uploaded.push({ key, size: file.size });

        // Cleanup temp file.
        try {
          fs.unlinkSync(file.path);
        } catch {
          // ignore cleanup errors
        }
      }

      return res.json({
        ok: true,
        message: `Uploaded ${uploaded.length} file(s) to R2.`,
        uploaded,
      });
    } catch (e) {
      // Cleanup temp files even on failure
      for (const file of files) {
        try {
          if (file.path) fs.unlinkSync(file.path);
        } catch {
          // ignore
        }
      }

      return res.status(500).json({
        message: "Upload failed",
        error: e?.message,
      });
    }
  },
);

// List objects in R2 by prefix (for showing uploaded files in the UI)
// Example:
//   GET /api/upload/list?prefix=uploads
//   GET /api/upload/list?prefix=demo
app.get("/api/upload/list", authRequired, async (req, res) => {
  const prefixRaw = req.query.prefix ?? "";
  const limitRaw = req.query.limit ?? "200";
  const delimiterRaw = req.query.delimiter ?? "true";

  const limit = Math.max(1, Math.min(Number(limitRaw) || 200, 1000));
  const prefixSafe = sanitizeRelativePath(prefixRaw);
  const prefix = prefixSafe
    ? prefixSafe.endsWith("/")
      ? prefixSafe
      : `${prefixSafe}/`
    : "";
  const delimiterEnabled =
    String(delimiterRaw).toLowerCase() === "true" ||
    String(delimiterRaw) === "1";

  try {
    const command = new ListObjectsV2Command({
      Bucket: R2_BUCKET,
      Prefix: prefix,
      MaxKeys: limit,
      ...(delimiterEnabled ? { Delimiter: "/" } : {}),
    });

    const data = await s3.send(command);
    const objects = (data.Contents || [])
      .filter((o) => o.Key)
      // Some providers include the folder placeholder equal to Prefix; hide it.
      .filter((o) => (prefix ? o.Key !== prefix : true))
      .map((o) => ({
        key: o.Key,
        size: o.Size,
      }));

    const folders = (data.CommonPrefixes || [])
      .map((p) => p.Prefix)
      .filter(Boolean);

    return res.json({ ok: true, prefix, delimiter: delimiterEnabled, folders, objects });
  } catch (e) {
    return res.status(500).json({
      ok: false,
      message: "Failed to list objects from R2",
      error: e?.message,
    });
  }
});

// Download an object from R2 (forces "Save as")
// Example: GET /api/download?key=uploads/team1/file.jpg
app.get("/api/download", authRequired, async (req, res) => {
  const keyRaw = req.query.key ?? "";
  const key = sanitizeRelativePath(keyRaw);
  if (!key) return res.status(400).json({ ok: false, message: "key is required" });

  try {
    const data = await s3.send(
      new GetObjectCommand({
        Bucket: R2_BUCKET,
        Key: key,
      }),
    );

    const filename = key.split("/").filter(Boolean).pop() || "file";
    const contentType = data.ContentType || "application/octet-stream";

    res.setHeader("Content-Type", contentType);
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    if (typeof data.ContentLength === "number") {
      res.setHeader("Content-Length", String(data.ContentLength));
    }

    // AWS SDK v3 returns a Readable stream for Body in Node.
    const body = data.Body;
    if (!body || typeof body.pipe !== "function") {
      return res.status(500).json({ ok: false, message: "Invalid object body" });
    }

    body.on("error", () => {
      try {
        res.end();
      } catch {
        // ignore
      }
    });



    
    return body.pipe(res);
  } catch (e) {
    return res.status(404).json({ ok: false, message: "Not found", error: e?.message });
  }
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`API running on http://localhost:${PORT}`);
});
