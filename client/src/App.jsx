import { useState, useCallback, useEffect, useRef } from "react";
import "./App.css";
import { notifyCriticalFindings } from "./alerts";
import { downloadJsonReport } from "./jsonReport";
import { downloadPdfReport } from "./pdfReport";

function severityClass(severity) {
  if (severity === "critical") return "critical";
  if (severity === "high") return "danger";
  if (severity === "medium") return "warn";
  return "low";
}

function App() {
  const [rootPath, setRootPath] = useState("");
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [fixing, setFixing] = useState(false);
  const [selected, setSelected] = useState(new Set());
  const [watching, setWatching] = useState(false);
  const [redactingKey, setRedactingKey] = useState(null);
  const [installingHook, setInstallingHook] = useState(false);
  const [toast, setToast] = useState(null);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [customRules, setCustomRules] = useState([]);
  const [ruleForm, setRuleForm] = useState({ name: "", pattern: "", severity: "medium", category: "" });
  const [addingRule, setAddingRule] = useState(false);
  const [deletingRuleId, setDeletingRuleId] = useState(null);
  const [allowlistOpen, setAllowlistOpen] = useState(false);
  const [allowlist, setAllowlist] = useState([]);
  const [ignoringKey, setIgnoringKey] = useState(null);
  const [unignoringId, setUnignoringId] = useState(null);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [exporting, setExporting] = useState(null);

  const eventSourceRef = useRef(null);
  const rescanTimerRef = useRef(null);
  const toastTimerRef = useRef(null);
  const exportMenuRef = useRef(null);

  const showToast = useCallback((type, message) => {
    clearTimeout(toastTimerRef.current);
    setToast({ type, message });
    toastTimerRef.current = setTimeout(() => setToast(null), 5000);
  }, []);

  useEffect(() => () => clearTimeout(toastTimerRef.current), []);

  useEffect(() => {
    fetch("/api/default-root")
      .then((res) => res.json())
      .then((data) => setRootPath(data.root))
      .catch(() => {});
  }, []);

  const runScan = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);
    try {
      const url = `/api/scan${rootPath ? `?root=${encodeURIComponent(rootPath)}` : ""}`;
      const res = await fetch(url);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Scan failed (${res.status})`);
      setScan(data);
      setSelected(new Set(data.envFiles.filter((f) => !f.ignored).map((f) => f.file)));

      const severeCount = data.secrets.filter(
        (s) => s.severity === "critical" || s.severity === "high"
      ).length;
      if (severeCount > 0) {
        notifyCriticalFindings(severeCount, data.root);
      }
    } catch (err) {
      setError(err.message);
      setScan(null);
    } finally {
      setLoading(false);
    }
  }, [rootPath]);

  // Live file watching: open an SSE stream for the scanned folder and
  // auto-rescan (debounced) whenever the backend reports a change.
  useEffect(() => {
    if (!scan?.root) return undefined;

    const es = new EventSource(`/api/watch?root=${encodeURIComponent(scan.root)}`);
    eventSourceRef.current = es;
    setWatching(true);

    es.addEventListener("change", () => {
      clearTimeout(rescanTimerRef.current);
      rescanTimerRef.current = setTimeout(() => runScan(true), 300);
    });

    es.onerror = () => setWatching(false);
    es.onopen = () => setWatching(true);

    return () => {
      clearTimeout(rescanTimerRef.current);
      es.close();
      if (eventSourceRef.current === es) eventSourceRef.current = null;
      setWatching(false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.root]);

  // Click-outside handling for the export format dropdown.
  useEffect(() => {
    if (!exportMenuOpen) return undefined;
    const handleClickOutside = (e) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target)) {
        setExportMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [exportMenuOpen]);

  const toggleSelected = (file) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(file)) next.delete(file);
      else next.add(file);
      return next;
    });
  };

  const fixSelected = async () => {
    if (selected.size === 0) return;
    setFixing(true);
    setError(null);
    try {
      const res = await fetch("/api/gitignore", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root: rootPath, paths: Array.from(selected) }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Fix failed (${res.status})`);
      await runScan();
    } catch (err) {
      setError(err.message);
    } finally {
      setFixing(false);
    }
  };

  const redactSecret = async (secret, key) => {
    setRedactingKey(key);
    setError(null);
    try {
      const res = await fetch("/api/redact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          root: rootPath,
          file: secret.file,
          line: secret.line,
          match: secret.match,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Redact failed (${res.status})`);
      await runScan();
    } catch (err) {
      setError(err.message);
    } finally {
      setRedactingKey(null);
    }
  };

  const installHook = async () => {
    setInstallingHook(true);
    try {
      const res = await fetch("/api/install-hook", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root: rootPath }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Install failed (${res.status})`);
      showToast(
        "success",
        data.updated
          ? "Pre-commit hook updated — it will now block commits containing secrets."
          : "Pre-commit hook installed — it will now block commits containing secrets."
      );
    } catch (err) {
      showToast("error", err.message);
    } finally {
      setInstallingHook(false);
    }
  };

  const loadCustomRules = useCallback(async () => {
    try {
      const res = await fetch("/api/custom-rules");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Failed to load rules (${res.status})`);
      setCustomRules(data.rules);
    } catch (err) {
      showToast("error", err.message);
    }
  }, [showToast]);

  const openRules = () => {
    setRulesOpen(true);
    loadCustomRules();
  };

  const addRule = async (e) => {
    e.preventDefault();
    setAddingRule(true);
    try {
      const res = await fetch("/api/custom-rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ruleForm),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Failed to add rule (${res.status})`);
      setCustomRules((prev) => [...prev, data]);
      setRuleForm({ name: "", pattern: "", severity: "medium", category: "" });
      showToast("success", `Custom rule "${data.name}" added.`);
    } catch (err) {
      showToast("error", err.message);
    } finally {
      setAddingRule(false);
    }
  };

  const deleteRule = async (rule) => {
    setDeletingRuleId(rule.id);
    try {
      const res = await fetch(`/api/custom-rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Failed to delete rule (${res.status})`);
      setCustomRules((prev) => prev.filter((r) => r.id !== rule.id));
      showToast("success", `Custom rule "${rule.name}" deleted.`);
    } catch (err) {
      showToast("error", err.message);
    } finally {
      setDeletingRuleId(null);
    }
  };

  const fetchAllowlistEntries = useCallback(async () => {
    const res = await fetch("/api/allowlist");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Failed to load allowlist (${res.status})`);
    setAllowlist(data.entries);
    return data.entries;
  }, []);

  const loadAllowlist = useCallback(async () => {
    try {
      await fetchAllowlistEntries();
    } catch (err) {
      showToast("error", err.message);
    }
  }, [fetchAllowlistEntries, showToast]);

  const openAllowlist = () => {
    setAllowlistOpen(true);
    loadAllowlist();
  };

  const exportReport = async (format) => {
    if (!scan) return;
    setExporting(format);
    try {
      const entries = await fetchAllowlistEntries();
      if (format === "json") {
        downloadJsonReport(scan, entries);
        showToast("success", "JSON audit downloaded — security-audit.json");
      } else {
        downloadPdfReport(scan, entries);
        showToast("success", "PDF report downloaded — security-audit-report.pdf");
      }
    } catch (err) {
      showToast("error", err.message);
    } finally {
      setExporting(null);
      setExportMenuOpen(false);
    }
  };

  const ignoreSecret = async (secret, key) => {
    setIgnoringKey(key);
    try {
      const res = await fetch("/api/allowlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "finding",
          file: secret.file,
          line: secret.line,
          match: secret.match,
          reason: "Marked as false positive from finding list",
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Failed to ignore finding (${res.status})`);
      showToast("success", `Ignored "${secret.type}" in ${secret.file}:${secret.line}.`);
      await runScan(true);
    } catch (err) {
      showToast("error", err.message);
    } finally {
      setIgnoringKey(null);
    }
  };

  const unignoreEntry = async (entry) => {
    setUnignoringId(entry.id);
    try {
      const res = await fetch(`/api/allowlist/${encodeURIComponent(entry.id)}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Failed to un-ignore (${res.status})`);
      setAllowlist((prev) => prev.filter((e) => e.id !== entry.id));
      showToast("success", `Un-ignored ${entry.file}${entry.line ? `:${entry.line}` : ""}. Rescanning…`);
      await runScan(true);
    } catch (err) {
      showToast("error", err.message);
    } finally {
      setUnignoringId(null);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") runScan();
  };

  const unignoredCount = scan?.envFiles.filter((f) => !f.ignored).length ?? 0;
  const exposedCount = unignoredCount + (scan?.secrets.length ?? 0);

  return (
    <div className="page">
      <div className="app">
        <header>
          <div className="brand">
            <span className="brand-icon">🧹</span>
            <div>
              <h1>Security Token Janitor</h1>
              <p className="subtitle">Scan any local folder for exposed .env files and leaked credentials</p>
            </div>
          </div>
        </header>

        <div className="scan-bar">
          <input
            className="path-input"
            type="text"
            placeholder="C:\path\to\your\project"
            value={rootPath}
            onChange={(e) => setRootPath(e.target.value)}
            onKeyDown={handleKeyDown}
            spellCheck={false}
          />
          <button className="scan-btn" onClick={() => runScan(false)} disabled={loading || !rootPath}>
            {loading ? "Scanning…" : "Scan"}
          </button>
          {scan && (
            <div className="export-menu" ref={exportMenuRef}>
              <button className="export-btn" onClick={() => setExportMenuOpen((v) => !v)}>
                Export Report ▾
              </button>
              {exportMenuOpen && (
                <div className="export-dropdown">
                  <button onClick={() => exportReport("json")} disabled={exporting !== null}>
                    {exporting === "json" ? "Exporting…" : "JSON Audit"}
                  </button>
                  <button onClick={() => exportReport("pdf")} disabled={exporting !== null}>
                    {exporting === "pdf" ? "Exporting…" : "PDF Report"}
                  </button>
                </div>
              )}
            </div>
          )}
          <button className="hook-btn" onClick={installHook} disabled={installingHook || !rootPath}>
            {installingHook ? "Installing…" : "Install Git Hook"}
          </button>
          <button className="rules-btn" onClick={openRules}>
            Custom Rules
          </button>
          <button className="rules-btn" onClick={openAllowlist}>
            Allowlist
          </button>
        </div>

        {error && <div className="error">{error}</div>}

        {scan && (
          <>
            <div className="summary-row">
              <div className={`summary-card ${exposedCount > 0 ? "danger" : "safe"}`}>
                <span className="summary-number">{exposedCount}</span>
                <span className="summary-label">Issues found</span>
              </div>
              <div className="summary-card">
                <span className="summary-number">{scan.envFiles.length}</span>
                <span className="summary-label">.env files</span>
              </div>
              <div className="summary-card">
                <span className="summary-number">{scan.secrets.length}</span>
                <span className="summary-label">Leaked secrets</span>
              </div>
              <div className="summary-meta">
                <span className={`live-indicator ${watching ? "on" : "off"}`}>
                  <span className="dot" />
                  {watching ? "Live watching" : "Not watching"}
                </span>
                Last scanned {new Date(scan.scannedAt).toLocaleTimeString()}
                <br />
                <code className="root-path">{scan.root}</code>
              </div>
            </div>

            <section className="panel">
              <h2>.env Files <span className="count">{scan.envFiles.length}</span></h2>
              {scan.envFiles.length === 0 && <p className="empty">No .env files found.</p>}
              <ul className="file-list">
                {scan.envFiles.map((f) => (
                  <li key={f.file} className={f.ignored ? "ok" : "warn"}>
                    <label>
                      <input
                        type="checkbox"
                        disabled={f.ignored}
                        checked={selected.has(f.file)}
                        onChange={() => toggleSelected(f.file)}
                      />
                      <code>{f.file}</code>
                    </label>
                    <span className={`badge ${f.ignored ? "" : "warn"}`}>
                      {f.ignored ? "ignored" : "exposed"}
                    </span>
                  </li>
                ))}
              </ul>
              {unignoredCount > 0 && (
                <button className="fix-btn" onClick={fixSelected} disabled={fixing || selected.size === 0}>
                  {fixing ? "Applying…" : `Add ${selected.size} selected to .gitignore`}
                </button>
              )}
            </section>

            <section className="panel">
              <h2>Potential Leaked Credentials <span className="count">{scan.secrets.length}</span></h2>
              {scan.secrets.length === 0 && <p className="empty">No suspicious credentials found.</p>}
              <ul className="secret-list">
                {scan.secrets.map((s) => {
                  const key = `${s.file}:${s.line}:${s.type}`;
                  return (
                    <li key={key}>
                      {s.category === "container" && (
                        <span className="badge container">🐳 Container/Infra</span>
                      )}
                      {s.custom && <span className="badge custom">⚙️ Custom: {s.category}</span>}
                      <span className={`badge ${severityClass(s.severity)}`}>{s.type}</span>
                      <span className="severity-label">{s.severity ?? "medium"}</span>
                      <code className="location">{s.file}:{s.line}</code>
                      <span className="preview">{s.preview}</span>
                      <button
                        className="redact-btn"
                        onClick={() => redactSecret(s, key)}
                        disabled={redactingKey === key}
                      >
                        {redactingKey === key ? "Redacting…" : "Redact Secret"}
                      </button>
                      <button
                        className="ignore-btn"
                        onClick={() => ignoreSecret(s, key)}
                        disabled={ignoringKey === key}
                      >
                        {ignoringKey === key ? "Ignoring…" : "Ignore / Suppress"}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </section>
          </>
        )}

        {!scan && !loading && !error && (
          <div className="hint">Enter a folder path above and hit Scan to get started.</div>
        )}
      </div>

      {rulesOpen && (
        <div className="modal-backdrop" onClick={() => setRulesOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Custom Rules</h2>
              <button className="modal-close" onClick={() => setRulesOpen(false)} aria-label="Close">
                ×
              </button>
            </div>
            <p className="modal-subtitle">
              Define your own regex-based detectors. They run alongside the built-in scanners on every scan.
            </p>

            <form className="rule-form" onSubmit={addRule}>
              <label className="full-width">
                Rule Name
                <input
                  type="text"
                  placeholder="Internal API Key"
                  value={ruleForm.name}
                  onChange={(e) => setRuleForm((f) => ({ ...f, name: e.target.value }))}
                  required
                />
              </label>
              <label className="full-width">
                Regex Pattern
                <input
                  className="mono"
                  type="text"
                  placeholder="INTERNAL_KEY_[A-Za-z0-9]{16}"
                  value={ruleForm.pattern}
                  onChange={(e) => setRuleForm((f) => ({ ...f, pattern: e.target.value }))}
                  spellCheck={false}
                  required
                />
              </label>
              <label>
                Severity
                <select
                  value={ruleForm.severity}
                  onChange={(e) => setRuleForm((f) => ({ ...f, severity: e.target.value }))}
                >
                  <option value="low">LOW</option>
                  <option value="medium">MEDIUM</option>
                  <option value="high">HIGH</option>
                  <option value="critical">CRITICAL</option>
                </select>
              </label>
              <label>
                Category
                <input
                  type="text"
                  placeholder="internal"
                  value={ruleForm.category}
                  onChange={(e) => setRuleForm((f) => ({ ...f, category: e.target.value }))}
                  required
                />
              </label>
              <button className="add-rule-btn" type="submit" disabled={addingRule}>
                {addingRule ? "Adding…" : "Add Rule"}
              </button>
            </form>

            <ul className="rule-list">
              {customRules.length === 0 && <p className="empty">No custom rules yet.</p>}
              {customRules.map((rule) => (
                <li key={rule.id}>
                  <span className="rule-name">{rule.name}</span>
                  <code className="rule-pattern">{rule.pattern}</code>
                  <span className={`badge ${severityClass(rule.severity)}`}>{rule.severity}</span>
                  <span className="rule-category">{rule.category}</span>
                  <button
                    className="rule-delete-btn"
                    onClick={() => deleteRule(rule)}
                    disabled={deletingRuleId === rule.id}
                  >
                    {deletingRuleId === rule.id ? "Deleting…" : "Delete"}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {allowlistOpen && (
        <div className="modal-backdrop" onClick={() => setAllowlistOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Allowlist</h2>
              <button className="modal-close" onClick={() => setAllowlistOpen(false)} aria-label="Close">
                ×
              </button>
            </div>
            <p className="modal-subtitle">
              Findings and files suppressed here are skipped on every future scan. Un-ignore an item to
              re-enable scanning on it and trigger an immediate rescan.
            </p>

            <ul className="rule-list">
              {allowlist.length === 0 && <p className="empty">Nothing is suppressed.</p>}
              {allowlist.map((entry) => (
                <li key={entry.id}>
                  <span className="rule-name">
                    {entry.type === "path" ? "📁 " : "🔇 "}
                    {entry.file}
                    {entry.line ? `:${entry.line}` : ""}
                  </span>
                  {entry.match && <code className="rule-pattern">{entry.match}</code>}
                  {entry.reason && <span className="rule-category">{entry.reason}</span>}
                  <button
                    className="rule-delete-btn"
                    onClick={() => unignoreEntry(entry)}
                    disabled={unignoringId === entry.id}
                  >
                    {unignoringId === entry.id ? "Un-ignoring…" : "Un-ignore"}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {toast && (
        <div className="toast-stack">
          <div className={`toast ${toast.type}`}>{toast.message}</div>
        </div>
      )}
    </div>
  );
}

export default App;
