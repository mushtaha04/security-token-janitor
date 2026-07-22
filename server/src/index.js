import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import chokidar from "chokidar";
import {
  scanProject,
  addToGitignore,
  redactSecret,
  installPreCommitHook,
  listCustomRules,
  addCustomRule,
  deleteCustomRule,
  listAllowlist,
  addAllowlistEntry,
  removeAllowlistEntry,
  IGNORED_DIRS,
} from "./scanner.js";

const app = express();
app.use(cors());
app.use(express.json());

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..", "..");

const cliArg = process.argv[2];
const DEFAULT_ROOT = path.resolve(cliArg || process.env.SCAN_ROOT || PROJECT_ROOT);

app.get("/api/default-root", (req, res) => {
  res.json({ root: DEFAULT_ROOT });
});

app.get("/api/scan", (req, res) => {
  const root = req.query.root ? path.resolve(String(req.query.root)) : DEFAULT_ROOT;

  if (!fs.existsSync(root)) {
    return res.status(400).json({ error: `Path does not exist: ${root}` });
  }
  if (!fs.statSync(root).isDirectory()) {
    return res.status(400).json({ error: `Not a directory: ${root}` });
  }

  try {
    const results = scanProject(root);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/gitignore", (req, res) => {
  const { root, paths } = req.body || {};
  if (!Array.isArray(paths) || paths.length === 0) {
    return res.status(400).json({ error: "paths must be a non-empty array" });
  }

  const targetRoot = root ? path.resolve(String(root)) : DEFAULT_ROOT;

  if (!fs.existsSync(targetRoot)) {
    return res.status(400).json({ error: `Path does not exist: ${targetRoot}` });
  }
  if (!fs.statSync(targetRoot).isDirectory()) {
    return res.status(400).json({ error: `Not a directory: ${targetRoot}` });
  }

  try {
    const result = addToGitignore(targetRoot, paths);
    res.json({ ...result, gitignorePath: path.join(targetRoot, ".gitignore") });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/redact", (req, res) => {
  const { root, file, line, match } = req.body || {};

  if (typeof file !== "string" || !file) {
    return res.status(400).json({ error: "file is required" });
  }
  if (!Number.isInteger(line) || line < 1) {
    return res.status(400).json({ error: "line must be a positive integer" });
  }
  if (typeof match !== "string" || !match) {
    return res.status(400).json({ error: "match is required" });
  }

  const targetRoot = root ? path.resolve(String(root)) : DEFAULT_ROOT;
  if (!fs.existsSync(targetRoot) || !fs.statSync(targetRoot).isDirectory()) {
    return res.status(400).json({ error: `Not a valid directory: ${targetRoot}` });
  }

  try {
    const result = redactSecret(targetRoot, file, line, match);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/install-hook", (req, res) => {
  const { root } = req.body || {};
  const targetRoot = root ? path.resolve(String(root)) : DEFAULT_ROOT;

  if (!fs.existsSync(targetRoot) || !fs.statSync(targetRoot).isDirectory()) {
    return res.status(400).json({ error: `Not a valid directory: ${targetRoot}` });
  }

  try {
    const result = installPreCommitHook(targetRoot);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/custom-rules", (req, res) => {
  try {
    res.json({ rules: listCustomRules() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/custom-rules", (req, res) => {
  const { name, pattern, severity, category } = req.body || {};
  try {
    const rule = addCustomRule({ name, pattern, severity, category });
    res.status(201).json(rule);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete("/api/custom-rules/:id", (req, res) => {
  try {
    const result = deleteCustomRule(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

app.get("/api/allowlist", (req, res) => {
  try {
    res.json({ entries: listAllowlist() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/allowlist", (req, res) => {
  const { type, file, line, match, reason } = req.body || {};
  try {
    const entry = addAllowlistEntry({ type, file, line, match, reason });
    res.status(201).json(entry);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete("/api/allowlist/:id", (req, res) => {
  try {
    const result = removeAllowlistEntry(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

const WATCH_IGNORE_GLOBS = [...IGNORED_DIRS].flatMap((dir) => [`**/${dir}/**`, `**/${dir}`]);

app.get("/api/watch", (req, res) => {
  const root = req.query.root ? path.resolve(String(req.query.root)) : DEFAULT_ROOT;

  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    return res.status(400).json({ error: `Not a valid directory: ${root}` });
  }

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write("retry: 3000\n\n");

  const watcher = chokidar.watch(root, {
    ignored: WATCH_IGNORE_GLOBS,
    ignoreInitial: true,
    persistent: true,
  });

  let debounceTimer = null;
  const scheduleNotify = (changedPath) => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      const relPath = path.relative(root, changedPath).split(path.sep).join("/");
      res.write(`event: change\ndata: ${JSON.stringify({ path: relPath, timestamp: Date.now() })}\n\n`);
    }, 400);
  };

  watcher.on("add", scheduleNotify);
  watcher.on("change", scheduleNotify);
  watcher.on("unlink", scheduleNotify);
  watcher.on("addDir", scheduleNotify);
  watcher.on("unlinkDir", scheduleNotify);
  watcher.on("error", (err) => {
    res.write(`event: error\ndata: ${JSON.stringify({ error: err.message })}\n\n`);
  });

  const heartbeat = setInterval(() => res.write(": heartbeat\n\n"), 20000);

  req.on("close", () => {
    clearInterval(heartbeat);
    clearTimeout(debounceTimer);
    watcher.close();
  });
});

const PORT = process.env.PORT || 4790;
app.listen(PORT, () => {
  console.log(`Token Janitor server listening on http://localhost:${PORT}`);
  console.log(`Default scan root: ${DEFAULT_ROOT}`);
});
