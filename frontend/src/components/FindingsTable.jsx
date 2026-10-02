const DECISION_CLASS = { redact: "decision-redact", review: "decision-review", skip: "decision-skip" };

export default function FindingsTable({ findings }) {
  if (!findings || findings.length === 0) {
    return <div className="empty-state">No findings yet — run a scan to see detected PII here.</div>;
  }

  return (
    <div className="table-wrap">
      <table className="doc-table">
        <thead>
          <tr>
            <th></th>
            <th>Entity</th>
            <th>Page</th>
            <th>Line</th>
            <th>Confidence</th>
            <th>Detected By</th>
            <th>Decision</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i}>
              <td><span className="redaction-swatch" aria-hidden="true" /></td>
              <td><span className="entity-tag">{f.entity_type}</span></td>
              <td>{f.page_number ?? (f.location ? f.location.replace("page ", "") : "—")}</td>
              <td>{f.line_number ?? "—"}</td>
              <td>{(f.score * 100).toFixed(0)}%</td>
              <td><span className="source-tag">{f.source}</span></td>
              <td>
                <span className={`decision-tag ${DECISION_CLASS[f.decision] || ""}`}>
                  {f.decision ?? "—"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
