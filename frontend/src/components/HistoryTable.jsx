function fmtDate(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

const STATUS_LABEL = {
  uploaded: "Intake",
  analyzed: "Scanned",
  redacted: "Redacted",
  failed: "Failed",
};

function VerifiedBadge({ verified, residualMatches, status }) {
  if (status !== "redacted") return <span className="source-tag">—</span>;
  if (verified === true) {
    return <span className="verify-badge pass">✓ Verified</span>;
  }
  if (verified === false) {
    return <span className="verify-badge fail">⚠ {residualMatches} residual</span>;
  }
  return <span className="source-tag">—</span>;
}

export default function HistoryTable({ documents }) {
  if (!documents || documents.length === 0) {
    return <div className="empty-state">No documents processed yet this session.</div>;
  }

  return (
    <div className="table-wrap">
      <table className="doc-table">
        <thead>
          <tr>
            <th>Filename</th>
            <th>Type</th>
            <th>Status</th>
            <th>Findings</th>
            <th>Verified</th>
            <th>Uploaded</th>
          </tr>
        </thead>
        <tbody>
          {documents.map((d) => (
            <tr key={d.id}>
              <td>{d.original_filename}</td>
              <td>{d.file_type.toUpperCase()}</td>
              <td>{STATUS_LABEL[d.status] || d.status}</td>
              <td>{d.entity_count}</td>
              <td><VerifiedBadge verified={d.verified} residualMatches={d.residual_matches} status={d.status} /></td>
              <td>{fmtDate(d.uploaded_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
