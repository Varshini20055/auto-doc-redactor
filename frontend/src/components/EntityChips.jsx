const ENTITY_TYPES = [
  "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
  "US_SSN", "IBAN_CODE", "LOCATION", "DATE_TIME", "IP_ADDRESS",
  "MEDICAL_LICENSE", "US_BANK_NUMBER", "CRYPTO", "URL", "NRP",
];

export default function EntityChips({ selected, onToggle }) {
  return (
    <div className="chip-row">
      {ENTITY_TYPES.map((type) => (
        <button
          key={type}
          type="button"
          className={`chip ${selected.includes(type) ? "active" : ""}`}
          onClick={() => onToggle(type)}
        >
          {type}
        </button>
      ))}
    </div>
  );
}

export { ENTITY_TYPES };
