import { useState, useRef, useEffect } from "react";
import axios from "axios";

const BACKEND_URL = ""; // proxied through Vite to 127.0.0.1:8000

const SUGGESTED = [
  "Where is the email address?",
  "Where are the phone numbers?",
  "Which page contains sensitive information?",
  "Show me all sensitive entity locations.",
  "Which findings were detected by the LLM?",
  "How many sensitive entities were found?",
];

export default function DocumentChatbot({ documentId }) {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "Ask me where sensitive information was detected in this document.",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = async (text) => {
    const msg = (text || input).trim();
    if (!msg || loading) return;
    setInput("");
    setMessages((prev) => [...prev, { role: "user", text: msg }]);
    setLoading(true);
    try {
      const res = await axios.post(
        `${BACKEND_URL}/documents/${documentId}/chat`,
        { message: msg }
      );
      const { answer, locations } = res.data;
      let display = answer;
      if (locations && locations.length > 0) {
        const grouped = {};
        for (const loc of locations) {
          const key = loc.entity_type;
          if (!grouped[key]) grouped[key] = [];
          grouped[key].push(loc);
        }
        const lines = Object.entries(grouped).map(([etype, locs]) => {
          const places = locs
            .map((l) =>
              l.page != null
                ? `Page ${l.page}${l.line != null ? `, Line ${l.line}` : ""}`
                : l.location || "—"
            )
            .join(" · ");
          return `${etype}: ${places}`;
        });
        display = answer + "\n\n" + lines.join("\n");
      }
      setMessages((prev) => [...prev, { role: "assistant", text: display }]);
    } catch (err) {
      const errMsg =
        err.response?.data?.detail || "Unable to reach the assistant. Please try again.";
      setMessages((prev) => [...prev, { role: "assistant", text: errMsg, error: true }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="chatbot-shell">
      <div className="chatbot-header">
        <div className="chatbot-title">Document Security Assistant</div>
        <div className="chatbot-subtitle">
          Ask where sensitive information was detected.
        </div>
      </div>

      <div className="chatbot-messages">
        {messages.map((m, i) => (
          <div key={i} className={`chat-msg ${m.role}${m.error ? " error" : ""}`}>
            <span className="chat-role">{m.role === "user" ? "You" : "A"}</span>
            <span className="chat-text">{m.text}</span>
          </div>
        ))}
        {loading && (
          <div className="chat-msg assistant">
            <span className="chat-role">A</span>
            <span className="chat-text chat-loading">
              <span />
              <span />
              <span />
            </span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className="chatbot-suggestions">
        {SUGGESTED.map((s) => (
          <button key={s} className="chat-suggestion" onClick={() => send(s)} disabled={loading}>
            {s}
          </button>
        ))}
      </div>

      <div className="chatbot-input-row">
        <input
          className="chatbot-input"
          type="text"
          placeholder="Ask about sensitive entity locations…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
          disabled={loading}
        />
        <button className="btn btn-primary chatbot-send" onClick={() => send()} disabled={!input.trim() || loading}>
          Send
        </button>
      </div>
    </div>
  );
}
