import { useRef, useState } from "react";

export default function Dropzone({ file, onSelect }) {
  const inputRef = useRef(null);
  const [dragActive, setDragActive] = useState(false);

  const handleFiles = (files) => {
    if (!files || files.length === 0) return;
    const f = files[0];
    const ext = f.name.split(".").pop().toLowerCase();
    if (ext !== "pdf" && ext !== "docx") {
      alert("Only .pdf and .docx files are supported.");
      return;
    }
    onSelect(f);
  };

  return (
    <div
      className={`dropzone ${dragActive ? "drag-active" : ""}`}
      onClick={() => inputRef.current?.click()}
      onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
      onDragLeave={() => setDragActive(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragActive(false);
        handleFiles(e.dataTransfer.files);
      }}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === "Enter") inputRef.current?.click(); }}
    >
      <div className="dropzone-icon" aria-hidden="true" />
      <div className="dropzone-text">
        <strong>Drop a document</strong> or click to browse
        <br />
        PDF or DOCX, up to 25MB
      </div>
      {file && (
        <div className="filename-chip">
          📄 {file.name}
        </div>
      )}
      <input
        ref={inputRef}
        type="file"
        accept=".pdf,.docx"
        onChange={(e) => handleFiles(e.target.files)}
      />
    </div>
  );
}
