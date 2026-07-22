function severityRank(severity) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity] ?? 4;
}

// Structured JSON export: totals broken down by severity/category, the
// allowlist rules that were active for this scan, and the full findings
// array (unfiltered by the UI — everything scanProject returned).
export function buildJsonReport(scan, allowlist) {
  const exposedEnv = scan.envFiles.filter((f) => !f.ignored);
  const sortedSecrets = [...scan.secrets].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  const bySeverity = {};
  const byCategory = {};
  for (const s of sortedSecrets) {
    const severity = s.severity ?? "medium";
    const category = s.category ?? "uncategorized";
    bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;
    byCategory[category] = (byCategory[category] ?? 0) + 1;
  }

  return {
    reportType: "Security Token Janitor Audit",
    generatedAt: new Date().toISOString(),
    scannedAt: scan.scannedAt,
    root: scan.root,
    summary: {
      totalIssues: exposedEnv.length + sortedSecrets.length,
      envFiles: { total: scan.envFiles.length, exposed: exposedEnv.length },
      secrets: { total: sortedSecrets.length, bySeverity, byCategory },
      allowlistedItems: allowlist.length,
    },
    allowlist,
    envFiles: scan.envFiles,
    secrets: sortedSecrets,
  };
}

export function downloadJsonReport(scan, allowlist) {
  const report = buildJsonReport(scan, allowlist);
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "security-audit.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
