"""
pipeline/pdf_ingestion.py
─────────────────────────
100% FREE — no API key, no LLM.
Uses pdfplumber for text extraction and regex/keyword logic for rule parsing.
"""
import re
import datetime
import hashlib
from typing import Any, Dict, List, Optional

# ── PDF extraction ────────────────────────────────────────────────────────────
try:
    import pdfplumber
    _PDFPLUMBER = True
except ImportError:
    _PDFPLUMBER = False


# ── Keyword patterns that indicate a compliance rule ─────────────────────────
_RULE_TRIGGERS = [
    r'\bmust\b', r'\bshall\b', r'\brequired?\b', r'\bprohibited?\b',
    r'\bmandatory\b', r'\bobligation\b', r'\bcompli\w+\b', r'\bpolicy\b',
    r'\bregulat\w+\b', r'\bstandard\b', r'\benforceable\b', r'\bpenalt\w+\b',
    r'\bviolat\w+\b', r'\bwarn\w+\b', r'\bsanction\b', r'\baudit\b',
    r'\bdisclose\b', r'\bretain\b', r'\bnotif\w+\b', r'\bapproval\b',
]
_RULE_RE = re.compile('|'.join(_RULE_TRIGGERS), re.IGNORECASE)

# ── Severity keywords ─────────────────────────────────────────────────────────
_SEVERITY_MAP = {
    'Critical': [r'\bcritical\b', r'\bimmediate\b', r'\bzero.toleran\w+\b',
                 r'\btermination\b', r'\bcriminal\b', r'\billegal\b', r'\bfraud\b'],
    'High':     [r'\bhigh\b', r'\bserious\b', r'\bsignificant\b', r'\bmajor\b',
                 r'\bsevere\b', r'\bviolat\w+\b', r'\bprohibit\w+\b'],
    'Medium':   [r'\bmedium\b', r'\bmoderate\b', r'\breviewed?\b', r'\bwarning\b',
                 r'\bescalat\w+\b', r'\baudit\b', r'\bdisclost?\w*\b'],
    'Low':      [r'\blow\b', r'\bminor\b', r'\badvisory\b', r'\brecommend\w+\b',
                 r'\bencourag\w+\b', r'\bbest.practic\w+\b'],
}
_SEVERITY_RES = {k: re.compile('|'.join(v), re.IGNORECASE) for k, v in _SEVERITY_MAP.items()}

# ── Category keywords ─────────────────────────────────────────────────────────
_CATEGORY_MAP = {
    'HR':           [r'\bemployee\b', r'\bhiring\b', r'\bbackground\b', r'\bconduct\b',
                     r'\bharassment\b', r'\bleave\b', r'\bperformance\b', r'\bnda\b'],
    'Legal/GDPR':   [r'\bGDPR\b', r'\bprivacy\b', r'\bdata.protect\w+\b', r'\bpersonal.data\b',
                     r'\bconsent\b', r'\bright.to.erasure\b', r'\bDPA\b'],
    'Financial':    [r'\bpayment\b', r'\binvoice\b', r'\bauditing\b', r'\bexpense\b',
                     r'\bfinancial\b', r'\bbudget\b', r'\btransaction\b', r'\bfraud\b'],
    'Security':     [r'\bpassword\b', r'\baccess.control\b', r'\bencrypt\w+\b', r'\bfirewall\b',
                     r'\bcybersecuri\w+\b', r'\bvulnerabilit\w+\b', r'\bincident\b'],
    'Operational':  [r'\bprocess\b', r'\bworkflow\b', r'\bprocedure\b', r'\bsop\b',
                     r'\boperat\w+\b', r'\bapproval\b', r'\bdocument\w+\b'],
}
_CATEGORY_RES = {k: re.compile('|'.join(v), re.IGNORECASE) for k, v in _CATEGORY_MAP.items()}


def _extract_text_from_pdf_bytes(pdf_bytes: bytes) -> str:
    """Extract all text from PDF bytes using pdfplumber."""
    if not _PDFPLUMBER:
        raise RuntimeError("pdfplumber not installed. Run: pip install pdfplumber")
    import io
    text_parts = []
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                text_parts.append(t)
    return "\n".join(text_parts)


def _infer_severity(text: str) -> str:
    for level in ('Critical', 'High', 'Medium', 'Low'):
        if _SEVERITY_RES[level].search(text):
            return level
    return 'Medium'


def _infer_category(text: str) -> str:
    for cat, pat in _CATEGORY_RES.items():
        if pat.search(text):
            return cat
    return 'Operational'


def _text_to_rules(text: str, source: str = "pdf") -> List[Dict[str, Any]]:
    """
    Split text into sentences, keep those that look like rules,
    and build structured rule dicts — no LLM needed.
    """
    # Split on sentence boundaries
    sentences = re.split(r'(?<=[.!?])\s+', text)
    rules = []
    seen = set()

    for sent in sentences:
        sent = sent.strip()
        # Must be substantial and contain a rule-trigger keyword
        if len(sent) < 30 or not _RULE_RE.search(sent):
            continue
        # Deduplicate by content hash
        h = hashlib.md5(sent.lower().encode()).hexdigest()[:8]
        if h in seen:
            continue
        seen.add(h)

        rule_id = f"PDF_{source[:6].upper()}_{h}"
        rules.append({
            "id":       rule_id,
            "text":     sent,
            "category": _infer_category(sent),
            "severity_hint": _infer_severity(sent),
            "source":   source,
        })

    return rules


# ── Public classes (same interface as before, no api_key needed) ──────────────

class CompliancePipeline:
    """Ingest PDFs and extract compliance rules — fully offline."""

    def __init__(self, api_key: Optional[str] = None):
        # api_key accepted for backward compatibility but never used
        pass

    def ingest_pdf_bytes(self, pdf_bytes: bytes, filename: str = "policy.pdf") -> Dict[str, Any]:
        text = _extract_text_from_pdf_bytes(pdf_bytes)
        rules = _text_to_rules(text, source=filename)
        return {
            "rules":        rules,
            "rules_count":  len(rules),
            "raw_text_len": len(text),
            "ingested_at":  datetime.datetime.utcnow().isoformat(),
        }

    def compare_policies(self, path_a: str, path_b: str) -> List[Dict[str, Any]]:
        """Find sentences in A that contradict sentences in B (keyword heuristic)."""
        with open(path_a, "rb") as f:
            text_a = _extract_text_from_pdf_bytes(f.read())
        with open(path_b, "rb") as f:
            text_b = _extract_text_from_pdf_bytes(f.read())

        rules_a = _text_to_rules(text_a, source=path_a)
        rules_b = _text_to_rules(text_b, source=path_b)

        conflicts = []
        _NEGATION = re.compile(
            r'\b(must not|shall not|prohibited|forbidden|not allowed|never)\b',
            re.IGNORECASE
        )
        _OBLIGATION = re.compile(
            r'\b(must|shall|required|mandatory|obligated)\b',
            re.IGNORECASE
        )

        for ra in rules_a:
            for rb in rules_b:
                # Same category, one obliges and the other forbids something similar
                if ra["category"] != rb["category"]:
                    continue
                a_neg = bool(_NEGATION.search(ra["text"]))
                b_neg = bool(_NEGATION.search(rb["text"]))
                a_obl = bool(_OBLIGATION.search(ra["text"]))
                b_obl = bool(_OBLIGATION.search(rb["text"]))
                # Conflict: one says MUST, other says MUST NOT in same category
                if (a_obl and b_neg) or (a_neg and b_obl):
                    # Crude token overlap to check same topic
                    words_a = set(re.findall(r'\b\w{4,}\b', ra["text"].lower()))
                    words_b = set(re.findall(r'\b\w{4,}\b', rb["text"].lower()))
                    overlap = len(words_a & words_b)
                    if overlap >= 2:
                        conflicts.append({
                            "rule_a": ra["id"],
                            "rule_b": rb["id"],
                            "description": (
                                f"Potential conflict: Policy A says '{ra['text'][:120]}…' "
                                f"but Policy B says '{rb['text'][:120]}…'"
                            ),
                            "category": ra["category"],
                            "overlap_score": overlap,
                        })
        return conflicts


class ViolationExplainer:
    """
    Explains violations in plain English — rule-based, no LLM.
    Falls back gracefully if api_key is missing (which it always will be now).
    """

    def __init__(self, api_key: Optional[str] = None):
        pass

    def explain(self, record: Dict[str, Any], rule: Dict[str, Any]) -> str:
        record_id   = record.get("id", "unknown")
        record_type = record.get("type", "record")
        rule_text   = rule.get("text", "")
        category    = rule.get("category", "policy")
        return (
            f"{record_type.capitalize()} '{record_id}' violates a {category} rule. "
            f"The policy states: \"{rule_text[:200]}\". "
            f"This record does not satisfy that requirement."
        )

    def suggest_fix(self, record_id: str, rule_text: str, explanation: str) -> str:
        # Keyword-driven fix suggestions
        rule_lower = rule_text.lower()
        if "background" in rule_lower:
            return f"Complete and verify background check for {record_id}."
        if "nda" in rule_lower or "non-disclosure" in rule_lower:
            return f"Obtain signed NDA from {record_id} immediately."
        if "gdpr" in rule_lower or "privacy" in rule_lower or "consent" in rule_lower:
            return f"Obtain valid data-processing consent from {record_id} and document it."
        if "password" in rule_lower or "access" in rule_lower:
            return f"Reset credentials and enforce access-control policy for {record_id}."
        if "payment" in rule_lower or "invoice" in rule_lower:
            return f"Review and reconcile payment records for {record_id}."
        if "training" in rule_lower or "certif" in rule_lower:
            return f"Enroll {record_id} in required compliance training."
        return f"Review record {record_id} against the policy and remediate non-compliance."


class SeverityScorer:
    """Re-scores severity based on explanation text — no LLM needed."""

    def score(self, explanation: str, default: str = "Medium") -> str:
        return _infer_severity(explanation) if explanation else default