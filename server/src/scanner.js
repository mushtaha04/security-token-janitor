import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CUSTOM_RULES_PATH = path.join(__dirname, "..", "data", "custom-rules.json");
const ALLOWLIST_PATH = path.join(__dirname, "..", "data", "allowlist.json");

export const IGNORED_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".cache",
  ".venv", "venv", "__pycache__", ".pytest_cache", "coverage",
  ".turbo", ".parcel-cache", ".svelte-kit", ".vercel", ".output",
  "target", "vendor", ".idea", ".vscode",
]);

const ENV_FILE_PATTERN = /^\.env(\..+)?$/i;
const REDACTION_PLACEHOLDER = "[REDACTED_BY_JANITOR]";

// [name, regex, severity] — regexes look for common provider key shapes in file content
const SECRET_PATTERNS = [
  ["Private Key (PEM/SSH)", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g, "critical"],
  ["AWS Access Key", /AKIA[0-9A-Z]{16}/g, "high"],
  ["AWS Secret Key", /(?:aws_secret_access_key|secret)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi, "high"],
  ["GitHub Token", /gh[pousr]_[A-Za-z0-9]{36,}/g, "high"],
  ["OpenAI/Anthropic Key", /sk-[A-Za-z0-9]{20,}/g, "high"],
  ["Slack Token", /xox[baprs]-[A-Za-z0-9-]{10,}/g, "high"],
  ["Slack Webhook URL", /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]{8,}\/B[A-Za-z0-9]{8,}\/[A-Za-z0-9]{16,}/g, "high"],
  ["Discord Bot Token", /[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/g, "high"],
  ["Stripe Key", /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g, "high"],
  ["Google API Key", /AIza[0-9A-Za-z\-_]{35}/g, "high"],
  ["Generic API Key Assignment", /(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9\-_.]{12,}["']/gi, "medium"],
];

const SCAN_EXTENSIONS = new Set([
  ".env", ".js", ".ts", ".jsx", ".tsx", ".py", ".json", ".yml", ".yaml",
  ".env.local", ".env.production", ".env.development", ".txt", ".cfg", ".ini", ".sh",
  ".pem", ".key", ".ppk", ".crt",
]);

const KEY_FILENAME_PATTERN = /^id_(rsa|dsa|ecdsa|ed25519)$/i;

// Container / infra file classifiers — used both to widen the scan (Dockerfiles
// have no extension) and to gate which container-specific rules apply to a file.
const DOCKERFILE_PATTERN = /^Dockerfile(\.[A-Za-z0-9_.-]+)?$/i;
const COMPOSE_FILE_PATTERN = /^(docker-)?compose(\.[A-Za-z0-9_.-]+)?\.ya?ml$/i;

function isKubernetesManifest(name, content) {
  if (!/\.ya?ml$/i.test(name)) return false;
  return /^apiVersion:/m.test(content) && /^kind:/m.test(content);
}

// [label, regex, severity, appliesTo] — container-specific rules, only run
// against files matching `appliesTo(filename, content)`. Each regex's single
// capturing group isolates the secret VALUE (not the whole "key: value" line)
// so redactSecret can blank out just the value and leave valid syntax behind.
// Leading/separator whitespace uses [ \t] rather than \s: JS multiline ^/$
// treat a lone \r as its own line terminator, so on CRLF files \s (which
// matches \r and \n) can let these classes swallow a newline and slide the
// match onto the next line, desyncing the reported line from the captured
// value. Restricting to space/tab keeps every match confined to one line.
const CONTAINER_SECRET_PATTERNS = [
  [
    "Dockerfile Hardcoded Secret (ENV/ARG)",
    /^[ \t]*(?:ENV|ARG)[ \t]+[A-Za-z0-9_]*(?:PASSWORD|PWD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL)[A-Za-z0-9_]*[ \t]*[=\t ]+["']?([^\s"'#][^\r\n"']*)/gim,
    "high",
    (name) => DOCKERFILE_PATTERN.test(name),
  ],
  [
    "Compose Exposed Database Password",
    /^[ \t-]*[A-Za-z][A-Za-z0-9_]*(?:PASSWORD|PWD)[A-Za-z0-9_]*[ \t]*[:=][ \t]*["']?(?!\$\{)([^\s"'#][^\r\n"']*)/gim,
    "high",
    (name) => COMPOSE_FILE_PATTERN.test(name),
  ],
];

function shouldScanFile(name) {
  if (ENV_FILE_PATTERN.test(name)) return true;
  if (KEY_FILENAME_PATTERN.test(name)) return true;
  if (DOCKERFILE_PATTERN.test(name)) return true;
  const ext = path.extname(name);
  return SCAN_EXTENSIONS.has(ext);
}

// Kubernetes `stringData:` blocks hold intentionally-plaintext secret values —
// flagging them requires tracking YAML indentation, not just a regex.
function findKubernetesStringDataSecrets(content) {
  const lines = content.split(/\r?\n/);
  const findings = [];
  let inStringData = false;
  let blockIndent = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const header = line.match(/^(\s*)stringData:\s*$/);
    if (header) {
      inStringData = true;
      blockIndent = header[1].length;
      continue;
    }
    if (!inStringData) continue;
    if (line.trim() === "") continue;

    const indent = line.match(/^(\s*)/)[1].length;
    if (indent <= blockIndent) {
      inStringData = false;
      continue;
    }
    const kv = line.match(/^\s*[\w.-]+:\s*["']?([^\r\n"']*)/);
    if (kv && kv[1] && kv[1] !== REDACTION_PLACEHOLDER) {
      findings.push({ line: i + 1, match: kv[1], preview: line.trim() });
    }
  }

  return findings;
}

// Kubernetes container `env:` entries with a secret-shaped name and a literal
// `value:` (rather than `valueFrom.secretKeyRef`) are hardcoded credentials.
function findKubernetesEnvSecrets(content) {
  const lines = content.split(/\r?\n/);
  const findings = [];
  const secretNamePattern = /(?:PASSWORD|PWD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL)/i;

  for (let i = 0; i < lines.length; i++) {
    const nameMatch = lines[i].match(/-\s*name:\s*([\w.-]+)/);
    if (!nameMatch || !secretNamePattern.test(nameMatch[1])) continue;

    const nextLine = lines[i + 1] || "";
    const valueMatch = nextLine.match(/^\s*value:\s*["']?([^\r\n"']*)/);
    if (!valueMatch) continue;

    const value = valueMatch[1].trim();
    if (!value || value.startsWith("${") || value === REDACTION_PLACEHOLDER) continue;

    findings.push({ line: i + 2, match: value, preview: nextLine.trim() });
  }

  return findings;
}

function walk(dir, root, results, customRules) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(root, fullPath).split(path.sep).join("/");

    if (entry.isDirectory()) {
      walk(fullPath, root, results, customRules);
      continue;
    }

    if (ENV_FILE_PATTERN.test(entry.name)) {
      results.envFiles.push(relPath);
    }

    if (!shouldScanFile(entry.name)) continue;

    let content;
    try {
      content = fs.readFileSync(fullPath, "utf8");
    } catch {
      continue;
    }

    for (const [label, regex, severity] of SECRET_PATTERNS) {
      regex.lastIndex = 0;
      const matches = content.match(regex);
      if (matches) {
        for (const match of new Set(matches)) {
          const lineNumber = content.slice(0, content.indexOf(match)).split("\n").length;
          results.secrets.push({
            file: relPath,
            type: label,
            severity,
            line: lineNumber,
            preview: match.length > 12 ? `${match.slice(0, 6)}...${match.slice(-4)}` : match,
            match,
          });
        }
      }
    }

    for (const [label, regex, severity, appliesTo] of CONTAINER_SECRET_PATTERNS) {
      if (!appliesTo(entry.name, content)) continue;
      regex.lastIndex = 0;
      let execMatch;
      while ((execMatch = regex.exec(content))) {
        const value = execMatch[1].replace(/[ \t]+$/, "");
        if (!value || value === REDACTION_PLACEHOLDER) continue;
        const fullMatch = execMatch[0];
        const lineNumber = content.slice(0, execMatch.index).split("\n").length;
        results.secrets.push({
          file: relPath,
          type: label,
          severity,
          line: lineNumber,
          preview: fullMatch.length > 60 ? `${fullMatch.slice(0, 40)}...` : fullMatch,
          match: value,
          category: "container",
        });
        if (execMatch.index === regex.lastIndex) regex.lastIndex++;
      }
    }

    for (const rule of customRules) {
      rule.regex.lastIndex = 0;
      const matches = content.match(rule.regex);
      if (matches) {
        for (const match of new Set(matches)) {
          const lineNumber = content.slice(0, content.indexOf(match)).split("\n").length;
          results.secrets.push({
            file: relPath,
            type: rule.name,
            severity: rule.severity,
            line: lineNumber,
            preview: match.length > 12 ? `${match.slice(0, 6)}...${match.slice(-4)}` : match,
            match,
            category: rule.category,
            custom: true,
          });
        }
      }
    }

    if (isKubernetesManifest(entry.name, content)) {
      for (const { line, match, preview } of findKubernetesStringDataSecrets(content)) {
        results.secrets.push({
          file: relPath,
          type: "Kubernetes Plaintext Secret (stringData)",
          severity: "critical",
          line,
          preview: preview.length > 60 ? `${preview.slice(0, 40)}...` : preview,
          match,
          category: "container",
        });
      }
      for (const { line, match, preview } of findKubernetesEnvSecrets(content)) {
        results.secrets.push({
          file: relPath,
          type: "Kubernetes Hardcoded Secret Value",
          severity: "high",
          line,
          preview: preview.length > 60 ? `${preview.slice(0, 40)}...` : preview,
          match,
          category: "container",
        });
      }
    }
  }
}

function readGitignore(root) {
  const gitignorePath = path.join(root, ".gitignore");
  try {
    return fs.readFileSync(gitignorePath, "utf8").split(/\r?\n/);
  } catch {
    return [];
  }
}

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

// A "path" entry suppresses a whole file (exact match or anything nested
// under it); a "finding" entry suppresses one specific file:line:match hit.
function isFindingAllowlisted(finding, allowlist) {
  return allowlist.some((entry) => {
    if (entry.file !== finding.file && !finding.file.startsWith(`${entry.file}/`)) return false;
    if (entry.type === "path") return true;
    return entry.line === finding.line && entry.match === finding.match;
  });
}

function isFileAllowlisted(relPath, allowlist) {
  return allowlist.some(
    (entry) => entry.type === "path" && (entry.file === relPath || relPath.startsWith(`${entry.file}/`))
  );
}

export function scanProject(root) {
  const results = { envFiles: [], secrets: [] };
  const customRules = compileCustomRules(loadCustomRules());
  walk(root, root, results, customRules);

  const gitignoreLines = readGitignore(root).map((l) => l.trim());
  const ignoredSet = new Set(gitignoreLines.filter(Boolean));

  const allowlist = loadAllowlist();

  const envFindings = results.envFiles
    .filter((relPath) => !isFileAllowlisted(relPath, allowlist))
    .map((relPath) => ({
      file: relPath,
      ignored: isPathIgnored(relPath, ignoredSet),
    }));

  const secrets = results.secrets
    .filter((finding) => !isFindingAllowlisted(finding, allowlist))
    .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3));

  return {
    root,
    envFiles: envFindings,
    secrets,
    scannedAt: new Date().toISOString(),
  };
}

function isPathIgnored(relPath, ignoredSet) {
  if (ignoredSet.has(relPath)) return true;
  const base = path.basename(relPath);
  if (ignoredSet.has(base)) return true;
  // matches a wildcard like ".env*" or ".env.*"
  for (const pattern of ignoredSet) {
    if (pattern.includes("*")) {
      const regex = new RegExp("^" + pattern.replace(/[.]/g, "\\.").replace(/\*/g, ".*") + "$");
      if (regex.test(base) || regex.test(relPath)) return true;
    }
  }
  return false;
}

export function redactSecret(root, relFile, line, match) {
  const resolvedRoot = path.resolve(root);
  const targetPath = path.resolve(resolvedRoot, relFile);
  if (targetPath !== resolvedRoot && !targetPath.startsWith(resolvedRoot + path.sep)) {
    throw new Error("file must resolve inside the scanned root");
  }
  if (!fs.existsSync(targetPath) || !fs.statSync(targetPath).isFile()) {
    throw new Error(`File does not exist: ${relFile}`);
  }

  const content = fs.readFileSync(targetPath, "utf8");
  const lines = content.split("\n");
  const index = line - 1;
  if (index < 0 || index >= lines.length) {
    throw new Error(`Line ${line} is out of range for ${relFile}`);
  }
  if (!lines[index].includes(match)) {
    throw new Error(`Match string not found on line ${line} of ${relFile}`);
  }

  lines[index] = lines[index].replace(match, REDACTION_PLACEHOLDER);
  fs.writeFileSync(targetPath, lines.join("\n"), "utf8");

  return { file: relFile, line, redacted: true };
}

const HOOK_START_MARKER = "# >>> security-token-janitor pre-commit hook >>>";
const HOOK_END_MARKER = "# <<< security-token-janitor pre-commit hook <<<";

// Extended-regex alternation for `grep -E`, mirroring a subset of
// SECRET_PATTERNS. Kept quote-free (no literal " or ' required around the
// generic key=value case) so the whole pattern can live in a plain
// double-quoted shell string without escaping headaches.
const HOOK_GREP_PATTERN =
  "-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----" +
  "|AKIA[0-9A-Z]{16}" +
  "|gh[pousr]_[A-Za-z0-9]{36,}" +
  "|sk-[A-Za-z0-9]{20,}" +
  "|xox[baprs]-[A-Za-z0-9-]{10,}" +
  "|(sk|rk)_(live|test)_[A-Za-z0-9]{16,}" +
  "|AIza[0-9A-Za-z_-]{35}" +
  "|(api[_-]?key|apikey|secret|token|password)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9_.-]{12,}";

function buildHookBlock() {
  return [
    HOOK_START_MARKER,
    "# Installed by Security Token Janitor. Blocks commits whose staged",
    "# changes contain likely secrets. Regenerate via POST /api/install-hook,",
    "# or bypass once with 'git commit --no-verify'.",
    "staged_files=$(git diff --cached --name-only --diff-filter=ACM)",
    "found=0",
    `pattern='${HOOK_GREP_PATTERN}'`,
    'for f in $staged_files; do',
    "  case \"$f\" in",
    "    node_modules/*|dist/*|build/*|.git/*) continue ;;",
    "  esac",
    '  if git show ":$f" 2>/dev/null | grep -EIq -- "$pattern"; then',
    '    echo "Security Token Janitor: possible secret detected in staged file: $f" >&2',
    "    found=1",
    "  fi",
    "done",
    'if [ "$found" -eq 1 ]; then',
    "  echo \"Commit blocked by Security Token Janitor. Remove or redact the secret(s) above, or run 'git commit --no-verify' to bypass.\" >&2",
    "  exit 1",
    "fi",
    HOOK_END_MARKER,
  ].join("\n");
}

export function installPreCommitHook(root) {
  const resolvedRoot = path.resolve(root);
  const gitDir = path.join(resolvedRoot, ".git");
  if (!fs.existsSync(gitDir) || !fs.statSync(gitDir).isDirectory()) {
    throw new Error("No .git folder found in the scanned root");
  }

  const hooksDir = path.join(gitDir, "hooks");
  fs.mkdirSync(hooksDir, { recursive: true });
  const hookPath = path.join(hooksDir, "pre-commit");

  const block = buildHookBlock();
  const existing = fs.existsSync(hookPath) ? fs.readFileSync(hookPath, "utf8") : "";

  let updated = false;
  let content;
  if (existing.includes(HOOK_START_MARKER) && existing.includes(HOOK_END_MARKER)) {
    const blockPattern = new RegExp(
      `${HOOK_START_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\\s\\S]*?${HOOK_END_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`
    );
    content = existing.replace(blockPattern, block);
    updated = true;
  } else if (existing.trim() === "") {
    content = `#!/bin/sh\n\n${block}\n`;
  } else {
    const needsNewline = !existing.endsWith("\n");
    content = `${existing}${needsNewline ? "\n" : ""}\n${block}\n`;
    updated = true;
  }

  fs.writeFileSync(hookPath, content, "utf8");
  fs.chmodSync(hookPath, 0o755);

  return { installed: true, updated, hookPath };
}

const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical"]);

function loadCustomRules() {
  let raw;
  try {
    raw = fs.readFileSync(CUSTOM_RULES_PATH, "utf8");
  } catch {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveCustomRules(rules) {
  fs.mkdirSync(path.dirname(CUSTOM_RULES_PATH), { recursive: true });
  fs.writeFileSync(CUSTOM_RULES_PATH, JSON.stringify(rules, null, 2) + "\n", "utf8");
}

// Rules that no longer compile (e.g. the config file was hand-edited into an
// invalid state) are silently skipped rather than failing the whole scan.
function compileCustomRules(rules) {
  const compiled = [];
  for (const rule of rules) {
    try {
      compiled.push({ ...rule, regex: new RegExp(rule.pattern, "g") });
    } catch {
      continue;
    }
  }
  return compiled;
}

export function listCustomRules() {
  return loadCustomRules();
}

export function addCustomRule({ name, pattern, severity, category }) {
  if (typeof name !== "string" || !name.trim()) {
    throw new Error("name is required");
  }
  if (typeof pattern !== "string" || !pattern.trim()) {
    throw new Error("pattern is required");
  }
  const normalizedSeverity = typeof severity === "string" ? severity.toLowerCase() : "";
  if (!VALID_SEVERITIES.has(normalizedSeverity)) {
    throw new Error("severity must be one of: low, medium, high, critical");
  }
  if (typeof category !== "string" || !category.trim()) {
    throw new Error("category is required");
  }

  try {
    new RegExp(pattern, "g");
  } catch (err) {
    throw new Error(`Invalid regular expression: ${err.message}`);
  }

  const rules = loadCustomRules();
  const rule = {
    id: crypto.randomUUID(),
    name: name.trim(),
    pattern,
    severity: normalizedSeverity,
    category: category.trim(),
    createdAt: new Date().toISOString(),
  };
  rules.push(rule);
  saveCustomRules(rules);
  return rule;
}

export function deleteCustomRule(id) {
  const rules = loadCustomRules();
  const next = rules.filter((r) => r.id !== id);
  if (next.length === rules.length) {
    throw new Error(`Custom rule not found: ${id}`);
  }
  saveCustomRules(next);
  return { deleted: true, id };
}

function loadAllowlist() {
  let raw;
  try {
    raw = fs.readFileSync(ALLOWLIST_PATH, "utf8");
  } catch {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveAllowlist(entries) {
  fs.mkdirSync(path.dirname(ALLOWLIST_PATH), { recursive: true });
  fs.writeFileSync(ALLOWLIST_PATH, JSON.stringify(entries, null, 2) + "\n", "utf8");
}

export function listAllowlist() {
  return loadAllowlist();
}

// { type: "path", file } suppresses a whole file (and anything nested under
// it, for directory-style paths); { type: "finding", file, line, match }
// suppresses one specific hit.
export function addAllowlistEntry({ type, file, line, match, reason }) {
  if (type !== "path" && type !== "finding") {
    throw new Error('type must be "path" or "finding"');
  }
  if (typeof file !== "string" || !file.trim()) {
    throw new Error("file is required");
  }

  const entry = {
    id: crypto.randomUUID(),
    type,
    file: file.trim(),
    reason: typeof reason === "string" ? reason.trim() : "",
    createdAt: new Date().toISOString(),
  };

  if (type === "finding") {
    if (!Number.isInteger(line) || line < 1) {
      throw new Error("line must be a positive integer");
    }
    if (typeof match !== "string" || !match) {
      throw new Error("match is required");
    }
    entry.line = line;
    entry.match = match;
  }

  const entries = loadAllowlist();
  entries.push(entry);
  saveAllowlist(entries);
  return entry;
}

export function removeAllowlistEntry(id) {
  const entries = loadAllowlist();
  const next = entries.filter((e) => e.id !== id);
  if (next.length === entries.length) {
    throw new Error(`Allowlist entry not found: ${id}`);
  }
  saveAllowlist(next);
  return { removed: true, id };
}

export function addToGitignore(root, relPaths) {
  const gitignorePath = path.join(root, ".gitignore");
  const existingLines = readGitignore(root);
  const existingSet = new Set(existingLines.map((l) => l.trim()).filter(Boolean));

  const toAdd = relPaths.filter((p) => !existingSet.has(p));
  if (toAdd.length === 0) {
    return { added: [] };
  }

  const needsLeadingNewline = existingLines.length > 0 && existingLines[existingLines.length - 1] !== "";
  const addition = (needsLeadingNewline ? "\n" : "") + toAdd.join("\n") + "\n";

  fs.appendFileSync(gitignorePath, addition, "utf8");
  return { added: toAdd };
}
