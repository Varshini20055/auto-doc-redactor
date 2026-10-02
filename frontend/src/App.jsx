import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";
import Dropzone from "./components/Dropzone.jsx";
import EntityChips from "./components/EntityChips.jsx";
import PipelineLedger from "./components/PipelineLedger.jsx";
import FindingsTable from "./components/FindingsTable.jsx";
import HistoryTable from "./components/HistoryTable.jsx";
import DocumentChatbot from "./components/DocumentChatbot.jsx";

const BACKEND_URL = ""; 

export default function App() {
  const [file, setFile] = useState(null);
  const [documentId, setDocumentId] = useState(null);
  const [selectedEntities, setSelectedEntities] = useState([]);
  const [findings, setFindings] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [downloadUrl, setDownloadUrl] = useState(null);
  const [certificateUrl, setCertificateUrl] = useState(null);
  const [verification, setVerification] = useState(null);
  const [showStamp, setShowStamp] = useState(false);
  const [analyzed, setAnalyzed] = useState(false);

  const [stepState, setStepState] = useState({});
  const [timestamps, setTimestamps] = useState({});

  const markStep = (key, state) => {
    setStepState((s) => ({ ...s, [key]: state }));
    if (state === "done") setTimestamps((t) => ({ ...t, [key]: Date.now() }));
  };
  

  useEffect(() => { refreshHistory(); }, []);

  const toggleEntity = (type) =>
    setSelectedEntities((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );

  const refreshHistory = async () => {
    try {
      const res = await axios.get(`${BACKEND_URL}/documents`);
      setDocuments(res.data);
    } catch { /* history is non-critical */ }
  };

  const handleSelect = (f) => {
    setFile(f);
    setDocumentId(null);
    setFindings([]);
    setDownloadUrl(null);
    setCertificateUrl(null);
    setVerification(null);
    setStepState({});
    setTimestamps({});
    setMessage(null);
    setShowStamp(false);
    setAnalyzed(false);
  };

  const upload = async () => {
    if (!file) return;
    setBusy(true);
    markStep("upload", "active");
    setMessage({ text: "Encrypting and storing original…", tone: "info" });
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await axios.post(`${BACKEND_URL}/documents/upload`, form);
      setDocumentId(res.data.id);
      markStep("upload", "done");
      setMessage({ text: `Received — document ID ${res.data.id.slice(0, 8)}…`, tone: "success" });
      refreshHistory();
    } catch (err) {
      markStep("upload", "error");
      setMessage({ text: err.response?.data?.detail || err.message, tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  const analyze = async () => {
    if (!documentId) return;
    setBusy(true);
    markStep("ocr", "active");
    setMessage({ text: "Extracting text (OCR if scanned)…", tone: "info" });
    try {
      const params = new URLSearchParams();
      selectedEntities.forEach((e) => params.append("entities", e));
      const res = await axios.post(`${BACKEND_URL}/documents/${documentId}/analyze?${params}`);

      const method = res.data.extraction_method || "text";
      markStep("ocr", "done");
      markStep("presidio", "done");
      markStep("llm", "done");
      markStep("crossverify", "done");

      setFindings(res.data.findings);
      setAnalyzed(true);
      const ocrNote = method.startsWith("ocr_") ? ` (OCR: ${method.replace("ocr_", "")})` : "";
      setMessage({
        text: `${res.data.entity_count} sensitive spans found${ocrNote}.`,
        tone: "success",
      });
      refreshHistory();
    } catch (err) {
      markStep("ocr", "error");
      setMessage({ text: err.response?.data?.detail || err.message, tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  const redact = async () => {
    if (!documentId) return;
    setBusy(true);
    markStep("redact", "active");
    setMessage({ text: "Stripping matched spans and scrubbing metadata…", tone: "info" });
    try {
      const params = new URLSearchParams();
      selectedEntities.forEach((e) => params.append("entities", e));
      const res = await axios.post(`${BACKEND_URL}/documents/${documentId}/redact?${params}`);
      markStep("redact", "done");
      markStep("verify", res.data.verified ? "done" : "error");
      markStep("download", "done");
      setDownloadUrl(`${BACKEND_URL}${res.data.download_url}`);
      setCertificateUrl(res.data.certificate_url ? `${BACKEND_URL}${res.data.certificate_url}` : null);
      setVerification({
        verified: res.data.verified,
        residualMatches: res.data.residual_matches,
        contextMatches: res.data.post_redaction_context_matches || 0,
        findings: res.data.verification_findings || [],
        warnings: res.data.warnings || [],
      });
      if (res.data.verified) {
        const contextNote = res.data.post_redaction_context_matches
          ? ` ${res.data.post_redaction_context_matches} post-redaction context match(es) were excluded from the failure count.`
          : "";
        setMessage({ text: `${res.data.redacted_boxes} spans redacted. Verified — no unmatched PII found.${contextNote}`, tone: "success" });
        setShowStamp(true);
      } else {
        setMessage({
          text: `${res.data.redacted_boxes} spans redacted, but verification found ${res.data.residual_matches} residual match(es) — review before sharing.`,
          tone: "error",
        });
      }
      refreshHistory();
    } catch (err) {
      markStep("redact", "error");
      setMessage({ text: err.response?.data?.detail || err.message, tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="shell">
      <header className="masthead">
        <div>
          <h1 className="masthead-title">
            <span className="masthead-mark" aria-hidden="true" />
            Auto-Doc Redactor
          </h1>
          <div className="masthead-sub">PII detection &amp; redaction workbench</div>
        </div>
        <div className="case-stamp">In review</div>
      </header>

      <p className="tagline">
        Upload a case file, scan it for personal and financial identifiers, and
        export a sanitized copy — with every step logged for audit.
      </p>

      <div className="workspace">
        <section className="panel">
          <h2 className="panel-label">Document intake</h2>
          <Dropzone file={file} onSelect={handleSelect} />

          <h2 className="panel-label" style={{ marginTop: 24 }}>
            Entity filter{" "}
            <span style={{ fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>
              (optional — leave empty for all)
            </span>
          </h2>
          <EntityChips selected={selectedEntities} onToggle={toggleEntity} />

          <div className="action-row">
            <button className="btn btn-primary" onClick={upload} disabled={!file || busy}>
              Upload
            </button>
            <button className="btn" onClick={analyze} disabled={!documentId || busy}>
              Scan
            </button>
            <button className="btn" onClick={redact} disabled={!documentId || busy}>
              Redact
            </button>
          </div>

          {message && (
            <div className={`status-banner ${message.tone === "error" ? "error" : message.tone === "success" ? "success" : ""}`}>
              {message.text}
            </div>
          )}

          {showStamp && (
            <div className="stamp-wrap">
              <div className="stamp">SANITIZED</div>
            </div>
          )}

          {verification && (
            <div className={`verify-panel ${verification.verified ? "pass" : "fail"}`}>
              <div className="verify-panel-title">
                {verification.verified
                  ? "✓ Verified — no unmatched PII detected"
                  : `⚠ Attention — ${verification.residualMatches} unmatched finding(s) remain in output`}
              </div>
              {verification.findings.length > 0 && (
                <ul className="verify-warnings">
                  {verification.findings.map((finding, i) => (
                    <li key={i}>
                      {finding.entity_type} — {finding.page_number != null ? `Page ${finding.page_number}` : finding.location}
                      {finding.line_number != null ? `, Line ${finding.line_number}` : ""} ({finding.category})
                    </li>
                  ))}
                </ul>
              )}
              {verification.warnings.length > 0 && (
                <ul className="verify-warnings">
                  {verification.warnings.map((w, i) => <li key={i}>{w}</li>)}
                </ul>
              )}
            </div>
          )}

          {downloadUrl && (
            <a className="download-link" href={downloadUrl} target="_blank" rel="noreferrer">
              ⬇ Download redacted copy
            </a>
          )}
          {certificateUrl && (
            <a className="download-link certificate-link" href={certificateUrl} target="_blank" rel="noreferrer">
              📄 Download redaction certificate
            </a>
          )}
        </section>

        <section className="panel">
          <h2 className="panel-label">Chain of custody</h2>
          <PipelineLedger stepState={stepState} timestamps={timestamps} />
        </section>
      </div>

      <div className="table-wrap">
        <h2 className="panel-label">Findings</h2>
        <FindingsTable findings={findings} />
      </div>

      <div className="table-wrap">
        <h2 className="panel-label">Document log</h2>
        <HistoryTable documents={documents} />
      </div>

      {analyzed && documentId && (
        <div className="table-wrap">
          <DocumentChatbot documentId={documentId} />
        </div>
      )}
    </div>
  );
}
