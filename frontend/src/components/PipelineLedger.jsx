const STEPS = [
  { key: "upload",   title: "01 · Intake",           desc: "Document received, encrypted at rest, checksum recorded." },
  { key: "ocr",      title: "02 · OCR / Extraction",  desc: "Text extracted via PyMuPDF (text PDF), PaddleOCR or Tesseract (scanned PDF), or python-docx (DOCX). Page, line, and bounding-box preserved." },
  { key: "presidio", title: "03 · Presidio + spaCy",  desc: "Regex + NER sweep for names, contacts, IDs, financial data — including tables and headers/footers." },
  { key: "llm",      title: "04 · LLM Context",       desc: "LLM analyzes contextual sensitivity: patient IDs, case numbers, medical records, indirect identifiers." },
  { key: "crossverify", title: "05 · Cross-Verify",   desc: "Presidio and LLM findings cross-verified. Overlapping spans merged with boosted confidence. Decision assigned per finding." },
  { key: "redact",   title: "06 · Redact",            desc: "Matches stripped from content stream. Scanned PDFs use bbox coordinates. Metadata, tracked changes, and comments scrubbed." },
  { key: "verify",   title: "07 · Verify",            desc: "Output independently re-scanned to confirm no residual PII remains." },
  { key: "download", title: "08 · Release",           desc: "Sanitized copy and signed certificate ready to export." },
];

function fmtTime(ts) {
  if (!ts) return null;
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function PipelineLedger({ stepState, timestamps }) {
  return (
    <ol className="ledger">
      {STEPS.map((step, i) => {
        const state = stepState[step.key] || "";
        return (
          <li key={step.key} className={`ledger-item ${state}`}>
            <div className="ledger-dot">
              {state === "done" ? "✓" : state === "error" ? "!" : i + 1}
            </div>
            <div>
              <div className="ledger-title">{step.title}</div>
              <div className="ledger-meta">{step.desc}</div>
              {timestamps[step.key] && (
                <div className="ledger-time">{fmtTime(timestamps[step.key])}</div>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
