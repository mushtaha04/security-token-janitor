import { jsPDF } from "jspdf";

const PAGE_WIDTH = 210;
const PAGE_HEIGHT = 297;
const MARGIN = 15;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;

const SEVERITY_COLORS = {
  critical: [255, 69, 58],
  high: [255, 123, 114],
  medium: [227, 179, 65],
  low: [139, 148, 158],
};

function severityRank(severity) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity] ?? 4;
}

function categoryLabel(finding) {
  if (finding.category === "container") return "Container / Infra";
  if (finding.custom) return `Custom Rule (${finding.category ?? "uncustomized"})`;
  return "Credentials";
}

// Tracks the current y cursor and starts a fresh page (re-drawing the running
// header) whenever content would overflow the bottom margin.
function makeCursor(doc) {
  let y = MARGIN;
  const ensureSpace = (needed) => {
    if (y + needed > PAGE_HEIGHT - MARGIN) {
      doc.addPage();
      y = MARGIN;
    }
  };
  return {
    get y() {
      return y;
    },
    set y(value) {
      y = value;
    },
    ensureSpace,
    advance(amount) {
      y += amount;
    },
  };
}

function drawHeaderBanner(doc, scan) {
  doc.setFillColor(13, 17, 23);
  doc.rect(0, 0, PAGE_WIDTH, 38, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("Security Token Janitor", MARGIN, 16);

  doc.setFontSize(12);
  doc.setFont("helvetica", "normal");
  doc.text("Security Audit Report", MARGIN, 24);

  doc.setFontSize(9);
  doc.setTextColor(200, 206, 214);
  doc.text(`Project path: ${scan.root}`, MARGIN, 31);
  doc.text(`Scanned at: ${new Date(scan.scannedAt).toLocaleString()}`, MARGIN, 36);

  doc.setTextColor(0, 0, 0);
}

function drawMetricBox(doc, x, y, width, height, label, value, color) {
  doc.setDrawColor(...color);
  doc.roundedRect(x, y, width, height, 2, 2, "S");

  doc.setTextColor(...color);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text(String(value), x + width / 2, y + height / 2 - 1, { align: "center" });

  doc.setTextColor(90, 98, 110);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.text(label, x + width / 2, y + height - 5, { align: "center", maxWidth: width - 6 });

  doc.setTextColor(0, 0, 0);
}

function drawExecutiveSummary(doc, cursor, scan, allowlist) {
  const exposedEnv = scan.envFiles.filter((f) => !f.ignored);
  const severeCount = scan.secrets.filter((s) => s.severity === "critical" || s.severity === "high").length;
  const totalIssues = exposedEnv.length + scan.secrets.length;

  cursor.ensureSpace(14);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("Executive Summary", MARGIN, cursor.y);
  cursor.advance(8);

  const boxWidth = (CONTENT_WIDTH - 3 * 6) / 4;
  const boxHeight = 22;
  const metrics = [
    ["Total Issues", totalIssues, totalIssues > 0 ? SEVERITY_COLORS.critical : [46, 160, 67]],
    ["High / Critical", severeCount, severeCount > 0 ? SEVERITY_COLORS.critical : [46, 160, 67]],
    [".env Files Exposed", exposedEnv.length, exposedEnv.length > 0 ? SEVERITY_COLORS.medium : [46, 160, 67]],
    ["Suppressed Items", allowlist.length, [88, 166, 255]],
  ];

  cursor.ensureSpace(boxHeight + 6);
  metrics.forEach(([label, value, color], i) => {
    drawMetricBox(doc, MARGIN + i * (boxWidth + 6), cursor.y, boxWidth, boxHeight, label, value, color);
  });
  cursor.advance(boxHeight + 10);
}

function drawEnvFilesSection(doc, cursor, scan) {
  cursor.ensureSpace(12);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text(".env Files", MARGIN, cursor.y);
  cursor.advance(7);

  if (scan.envFiles.length === 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor(90, 98, 110);
    doc.text("No .env files found.", MARGIN, cursor.y);
    doc.setTextColor(0, 0, 0);
    cursor.advance(8);
    return;
  }

  doc.setFontSize(9.5);
  for (const f of scan.envFiles) {
    cursor.ensureSpace(6);
    doc.setFont("courier", "normal");
    doc.setTextColor(0, 0, 0);
    doc.text(f.file, MARGIN, cursor.y, { maxWidth: CONTENT_WIDTH - 30 });

    doc.setFont("helvetica", "bold");
    doc.setTextColor(...(f.ignored ? [46, 160, 67] : SEVERITY_COLORS.high));
    doc.text(f.ignored ? "IGNORED" : "EXPOSED", MARGIN + CONTENT_WIDTH - 25, cursor.y);
    doc.setTextColor(0, 0, 0);
    cursor.advance(6);
  }
  cursor.advance(4);
}

function drawSecretsSection(doc, cursor, scan) {
  cursor.ensureSpace(12);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("Detected Secrets", MARGIN, cursor.y);
  cursor.advance(8);

  const sorted = [...scan.secrets].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  if (sorted.length === 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor(90, 98, 110);
    doc.text("No suspicious credentials found.", MARGIN, cursor.y);
    doc.setTextColor(0, 0, 0);
    cursor.advance(8);
    return;
  }

  const groups = new Map();
  for (const finding of sorted) {
    const label = categoryLabel(finding);
    if (!groups.has(label)) groups.set(label, []);
    groups.get(label).push(finding);
  }

  for (const [label, findings] of groups) {
    cursor.ensureSpace(10);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10.5);
    doc.setTextColor(88, 166, 255);
    doc.text(label, MARGIN, cursor.y);
    doc.setTextColor(0, 0, 0);
    cursor.advance(6);

    for (const finding of findings) {
      cursor.ensureSpace(12);
      const color = SEVERITY_COLORS[finding.severity] ?? SEVERITY_COLORS.medium;

      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(...color);
      doc.text((finding.severity ?? "medium").toUpperCase(), MARGIN, cursor.y);

      doc.setTextColor(0, 0, 0);
      doc.text(finding.type, MARGIN + 22, cursor.y, { maxWidth: CONTENT_WIDTH - 22 });
      cursor.advance(5);

      doc.setFont("courier", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(90, 98, 110);
      doc.text(`${finding.file}:${finding.line}`, MARGIN + 4, cursor.y, { maxWidth: CONTENT_WIDTH - 4 });
      cursor.advance(4.5);

      doc.setTextColor(140, 90, 40);
      doc.text(`preview: ${finding.preview}`, MARGIN + 4, cursor.y, { maxWidth: CONTENT_WIDTH - 4 });
      doc.setTextColor(0, 0, 0);
      cursor.advance(7);
    }
    cursor.advance(2);
  }
}

function drawFooter(doc) {
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(140, 148, 158);
    doc.text("Generated by Security Token Janitor", MARGIN, PAGE_HEIGHT - 8);
    doc.text(`Page ${i} of ${pageCount}`, PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 8, { align: "right" });
    doc.setTextColor(0, 0, 0);
  }
}

export function buildPdfReport(scan, allowlist) {
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  drawHeaderBanner(doc, scan);

  const cursor = makeCursor(doc);
  cursor.y = 46;

  drawExecutiveSummary(doc, cursor, scan, allowlist);
  drawEnvFilesSection(doc, cursor, scan);
  drawSecretsSection(doc, cursor, scan);
  drawFooter(doc);

  return doc;
}

export function downloadPdfReport(scan, allowlist) {
  const doc = buildPdfReport(scan, allowlist);
  doc.save("security-audit-report.pdf");
}
