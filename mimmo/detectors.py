"""Detector framework and built-in rules.

A detector is a small object with up to three optional methods:

    scan_text(text, source, apk)        -> Iterator[Finding]
    scan_binary(data, source, apk)      -> Iterator[Finding]
    scan_manifest(elements, source, apk)-> Iterator[Finding]

The scanner only calls the methods that make sense for each artifact:
text-like files go to ``scan_text``; ``AndroidManifest.xml`` goes to
``scan_manifest`` after AXML parsing; everything else (DEX, ARSC, small
unknown binaries) gets converted to a string-pool first and then fed to
``scan_text``.

Add new detectors by subclassing :class:`Detector` and decorating with
:func:`register`. They will be picked up automatically by ``Scanner``.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator, List, Optional

from .finding import Finding


# -----------
# Registry---


class Detector:
    """Base class for all detectors. Override the methods you need."""

    name: str = "base"
    category: str = "generic"

    def scan_text(self, text: str, source: str, apk: str) -> Iterator[Finding]:
        return iter(())

    def scan_manifest(
        self, elements: Iterable, source: str, apk: str
    ) -> Iterator[Finding]:
        return iter(())


_REGISTRY: List[Detector] = []


def register(cls):
    """Class decorator that registers an instance of the detector."""
    _REGISTRY.append(cls())
    return cls


def get_all() -> List[Detector]:
    """Return a copy of all registered detectors."""
    return list(_REGISTRY)


# ----------------------
# Pattern definitions
# ------------------------
#
# Each tuple is (rule_name, regex, confidence, category, description).
# Patterns with very specific, well-known shapes get high confidence;
# generic ones get medium and are filtered through a placeholder check
# to drop obvious template values like "YOUR_API_KEY".

# High-signal vendor patterns.
SECRET_PATTERNS: List[tuple] = [
    ("google_api_key",
     r"AIza[0-9A-Za-z_\-]{35}",
     0.95, "secret", "Google API key (Maps, Firebase, Cloud, ...)"),
    ("aws_access_key",
     r"\bAKIA[0-9A-Z]{16}\b",
     0.95, "secret", "AWS Access Key ID"),
    ("aws_session_key",
     r"\bASIA[0-9A-Z]{16}\b",
     0.9, "secret", "AWS Temporary Session Key ID"),
    ("github_pat_classic",
     r"\bghp_[A-Za-z0-9]{36}\b",
     0.95, "secret", "GitHub Personal Access Token (classic)"),
    ("github_oauth",
     r"\bgho_[A-Za-z0-9]{36}\b",
     0.95, "secret", "GitHub OAuth access token"),
    ("github_app",
     r"\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b",
     0.9, "secret", "GitHub App user/server token"),
    ("github_pat_fine",
     r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
     0.95, "secret", "GitHub fine-grained Personal Access Token"),
    ("slack_token",
     r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
     0.9, "secret", "Slack token"),
    ("slack_webhook",
     r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
     0.95, "secret", "Slack incoming webhook"),
    ("stripe_live_secret",
     r"\bsk_live_[0-9a-zA-Z]{24,}\b",
     0.95, "secret", "Stripe live secret key"),
    ("stripe_restricted",
     r"\brk_live_[0-9a-zA-Z]{24,}\b",
     0.95, "secret", "Stripe restricted live key"),
    ("stripe_pub_live",
     r"\bpk_live_[0-9a-zA-Z]{24,}\b",
     0.5, "secret", "Stripe live publishable key (public, but reveals account)"),
    ("twilio_account_sid",
     r"\bAC[a-f0-9]{32}\b",
     0.55, "secret", "Twilio Account SID (often paired with auth token)"),
    ("twilio_api_key",
     r"\bSK[a-f0-9]{32}\b",
     0.85, "secret", "Twilio API key"),
    ("sendgrid_api_key",
     r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
     0.95, "secret", "SendGrid API key"),
    ("mailgun_api_key",
     r"\bkey-[0-9a-zA-Z]{32}\b",
     0.7, "secret", "Mailgun API key"),
    # Full PEM block: BEGIN header + body + END footer. (?s) enables DOTALL
    # so [\s\S] matches newlines; the lazy *? prevents the regex from
    # gluing two unrelated keys together if both appear in the same blob.
    # Length cap of 8192 chars is a sanity ceiling — real RSA-4096 PEMs
    # are ~3.4KB, EC keys ~250B, so this comfortably covers everything.
    ("private_key_pem",
     r"(?s)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
     r".{1,8192}?"
     r"-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
     0.98, "secret", "Embedded private key (full PEM block)"),
    # Fallback: orphan header without an END marker. Happens when the
    # key body is concatenated at runtime from several DEX strings, or
    # when the asset has been truncated. Lower confidence — could still
    # mean a real key is reachable, just not in this single string.
    ("private_key_pem_header",
     r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
     0.75, "secret",
     "PEM private-key header without matching END (body may be split "
     "across DEX strings or truncated; check surrounding code)"),
    ("jwt_token",
     # eyJ = base64url("{") opening JSON; three b64url segments.
     r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
     0.85, "secret", "JSON Web Token (JWT)"),
    ("bearer_token",
     r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}",
     0.7, "secret", "HTTP Bearer Authorization header"),
    ("basic_auth",
     r"[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}",
     0.6, "secret", "HTTP Basic Authorization header"),
    ("firebase_db_url",
     r"https?://[a-z0-9\-]+\.firebaseio\.com",
     0.7, "secret", "Firebase Realtime Database URL"),
    ("gcp_service_account",
     r'"type"\s*:\s*"service_account"',
     0.85, "secret",
     "GCP service-account JSON marker (likely a private_key follows)"),
    # ---- Additional vendor patterns -------------------------------------
    ("square_access_token",
     r"\bsq0atp-[0-9A-Za-z_\-]{22}\b",
     0.95, "secret", "Square production access token"),
    ("square_oauth_secret",
     r"\bsq0csp-[0-9A-Za-z_\-]{43}\b",
     0.95, "secret", "Square OAuth secret"),
    ("paypal_braintree",
     r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b",
     0.95, "secret", "PayPal/Braintree production access token"),
    ("mailchimp_api_key",
     r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
     0.85, "secret", "Mailchimp API key"),
    ("twilio_auth_token",
     r"\bSK[0-9a-f]{32}\b",
     0.7, "secret", "Twilio auth token (SK*) — context required"),
    ("openai_api_key",
     r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b",
     0.95, "secret", "OpenAI API key (legacy format)"),
    ("openai_project_key",
     r"\bsk-proj-[A-Za-z0-9_\-]{40,}\b",
     0.95, "secret", "OpenAI project-scoped API key"),
    ("anthropic_api_key",
     r"\bsk-ant-[a-z0-9]{2,5}-[A-Za-z0-9_\-]{80,}\b",
     0.95, "secret", "Anthropic Claude API key"),
    ("huggingface_token",
     r"\bhf_[A-Za-z0-9]{34}\b",
     0.95, "secret", "Hugging Face access token"),
    ("digitalocean_pat",
     r"\bdop_v1_[a-f0-9]{64}\b",
     0.95, "secret", "DigitalOcean personal access token"),
    ("heroku_api_key",
     r"\bheroku[_\-]?(?:api[_\-]?key|token)['\"]?\s*[:=]\s*['\"]?"
     r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
     0.85, "secret", "Heroku API key (UUID-shaped, contextual)"),
    ("cloudflare_api_token",
     r"\b(?:cf|cloudflare)[_\-]?(?:api[_\-]?)?token['\"]?\s*[:=]\s*['\"]?"
     r"[A-Za-z0-9_\-]{40}\b",
     0.85, "secret", "Cloudflare API token (contextual)"),
    ("npm_token",
     r"\bnpm_[A-Za-z0-9]{36}\b",
     0.95, "secret", "npm access token"),
    ("pypi_token",
     r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b",
     0.95, "secret", "PyPI API token"),
    ("discord_bot_token",
     r"\b[MN][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6,7}\.[A-Za-z0-9_\-]{27,40}\b",
     0.9, "secret", "Discord bot token"),
    ("discord_webhook",
     r"https?://(?:discord(?:app)?|canary\.discord)\.com/api/webhooks/\d+/[\w\-]+",
     0.9, "secret", "Discord webhook URL"),
    ("telegram_bot_token",
     r"\b\d{8,12}:AA[A-Za-z0-9_\-]{32,35}\b",
     0.95, "secret", "Telegram Bot API token"),
    ("algolia_admin_key",
     r"(?i)\balgolia[_\-]?admin[_\-]?(?:api[_\-]?)?key['\"]?\s*[:=]\s*['\"]?[a-f0-9]{32}\b",
     0.9, "secret", "Algolia admin API key"),
    # ---- Hard-coded crypto material -------------------------------------
    # AES-128/192/256 key declared as hex literal — heuristic but very useful.
    ("aes_key_hex",
     r"(?i)(?:aes[_\-]?key|secret[_\-]?key|encryption[_\-]?key)['\"]?"
     r"\s*[:=]\s*['\"]([0-9a-f]{32}|[0-9a-f]{48}|[0-9a-f]{64})['\"]",
     0.8, "secret", "Possible hard-coded AES key (hex literal)"),
]

# Heuristic key=value style patterns (lower confidence, placeholder-filtered).
HEURISTIC_PATTERNS: List[tuple] = [
    ("hardcoded_credential",
     r"""(?ix)
        (?:^|[\s;,{(\[])
        (password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret)
        \s*[:=]\s*
        ['"]([^'"\s]{6,})['"]
     """,
     0.65, "secret", "Hardcoded credential assignment"),
    # Very generic: long high-entropy hex/base64 blobs assigned to a
    # variable. Caught last so vendor patterns claim their tokens first.
    ("high_entropy_blob",
     r"""(?ix)
        (?:^|[\s;,{(\[])
        ([A-Za-z][A-Za-z0-9_\-]{2,30})
        \s*[:=]\s*
        ['"]([A-Za-z0-9+/=_\-]{32,})['"]
     """,
     0.55, "secret",
     "High-entropy string literal — possible token/key (entropy-filtered)"),
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# URL pattern: liberal, then we strip trailing punctuation and filter noise.
URL_RE = re.compile(r"https?://[^\s'\"<>`{}|\\^]+", re.ASCII)

# Recognises XML/XSD/W3C namespace declarations and Android schemas - not
# real endpoints.
URL_NOISE_RE = re.compile(
    r"^https?://"
    r"(?:"
    r"schemas\.[^/]+|"
    r"www\.w3\.org|"
    r"xmlns\.[^/]+|"
    r"ns\.adobe\.com|"
    r"java\.sun\.com|"
    r"xml\.apache\.org|"
    r"goo\.gl/[a-z]"   # Google docs links etc., not interesting endpoints
    r")",
    re.IGNORECASE,
)

# RFC1918 / loopback / link-local: things that should never ship in prod.
INTERNAL_HOST_RE = re.compile(
    r"^https?://("
    r"localhost|"
    r"127(?:\.\d{1,3}){3}|"
    r"10(?:\.\d{1,3}){3}|"
    r"192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|"
    r"169\.254(?:\.\d{1,3}){2}"
    r")(?::\d+)?(?:/|$)",
    re.IGNORECASE,
)

# Bare IPv4 with optional port. Word boundaries (\b) prevent matching
# the middle of version strings like "1.2.3.4.5". The negative lookahead
# `(?!\.\d)` after the last octet rejects "1.2.3.4.5" outright. This is
# the regex that catches reverse_tcp / reverse_https C2 hosts that
# malware (msfvenom payloads, RATs) embeds as plain strings.
BARE_IPV4_RE = re.compile(
    r"\b("
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"      # octet 1
    r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}"  # octets 2-4
    r")"
    r"(?::(\d{1,5}))?"                       # optional :port
    r"(?!\.?\d)",                            # not followed by another octet/digit
    re.ASCII,
)

# IPs that are obvious noise: 0.0.0.0, 255.255.255.255, broadcast/null,
# version-string-ish ranges (1.0.0.0, 2.0.0.0...), and the Google DNS
# anycast addresses which appear in network-config code constantly.
_NOISE_IP_RE = re.compile(
    r"^(?:"
    r"0\.0\.0\.0|"
    r"255\.255\.255\.255|"
    r"255\.255\.255\.0|"
    r"0\.0\.0\.\d+|"
    r"\d+\.0\.0\.0"
    r")$"
)

# Private/loopback/link-local IP classifier (returns True for IPs that
# warrant flagging as internal endpoints when seen as bare strings).
_PRIVATE_IP_RE = re.compile(
    r"^(?:"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3}"
    r")$"
)


# Strings whose presence in classes.dex strongly indicates a Metasploit
# Android stager / Meterpreter payload, or another known RAT family.
# These are stable across msfvenom versions because they're the package
# names and method names the runtime needs to resolve at startup.
MALWARE_SIGNATURE_PATTERNS = [
    ("metasploit_payload",
     # Match both Java FQN (com.metasploit.stage) and DEX descriptor
     # form (Lcom/metasploit/stage). msfvenom embeds the latter; the
     # original regex only matched the former and missed every payload.
     r"\b(?:L?com[./]metasploit[./](?:stage|meterpreter))\b",
     0.99, "secret",
     "Metasploit Android payload package — APK is almost certainly "
     "a meterpreter stager or generated by msfvenom."),
    ("meterpreter_marker",
     r"\b(?:meterpreter|metsrv|stdapi_|priv_)\b",
     0.95, "secret",
     "Meterpreter command/extension marker (stdapi/priv) — strongly "
     "suggests a meterpreter payload."),
    ("metasploit_stager_class",
     r"\bPayload\$\d|\bcom/metasploit/stage/Payload\b",
     0.99, "secret",
     "Metasploit stager class reference."),
    ("generic_rat_marker",
     r"\b(?:AhMyth|SpyNote|DroidJack|AndroRAT|cerberus_bot|alien_bot)\b",
     0.95, "secret",
     "Known Android RAT family marker string."),
    ("reverse_shell_method",
     r"\b(?:reverseShell|connectBack|callHome|c2_url|cncServer)\b",
     0.85, "secret",
     "Function/variable name typical of reverse-shell / C2 logic."),
]


# ---------
# Helpers
# -------


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. Used to filter heuristic findings.

    Empirical thresholds (measured on real-world samples):
      < 3.0 = English / code identifiers / placeholder text
      3.0-3.5 = mixed natural strings (paths, log lines)
      3.5-4.0 = base64 of structured data, version strings
      > 4.0 = real high-entropy tokens (UUIDs, crypto material, JWT b64)

    We require >= 3.5 to flag a generic blob, which kills 90% of the
    false-positive heuristic matches without losing real secrets.
    """
    if not s:
        return 0.0
    from math import log2
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in freq.values())


def _truncate(s: str, maxlen: int = 200) -> str:
    """Cap value length so a giant blob (e.g. a base64-encoded cert) doesn't
    pollute the output. Keep enough to identify the finding."""
    if len(s) <= maxlen:
        return s
    return s[: maxlen - 14] + "...<truncated>"


# Per-rule overrides for the value-length cap. PEM blocks legitimately
# run 1500-3500 chars (RSA-2048..4096); the default 200 would amputate
# the body and hide the actual key material from the report.
_VALUE_MAXLEN_OVERRIDES = {
    "private_key_pem": 8192,
}


_PLACEHOLDER_TOKENS = (
    "your_", "yourkey", "<your", "xxxxx", "changeme", "password123",
    "example", "sample", "placeholder", "todo", "lorem", "fixme",
    "dummy", "fake", "test_token", "abc123",
)


def _looks_like_placeholder(value: str) -> bool:
    """Heuristic to drop obvious template strings from the credential pattern."""
    v = value.lower()
    if any(tok in v for tok in _PLACEHOLDER_TOKENS):
        return True
    if v in {"password", "secret", "token", "apikey", "key", "null", "none"}:
        return True
    if re.fullmatch(r"[*x]{4,}", v) or re.fullmatch(r"\${[^}]+}", value):
        return True
    return False


_NOISE_EMAIL_DOMAINS = (
    "@example.com", "@example.org", "@test.com", "@email.com",
    "@domain.com", "@yourcompany.com", "@your-domain.com",
)


def _is_noise_email(value: str) -> bool:
    v = value.lower()
    return any(v.endswith(d) for d in _NOISE_EMAIL_DOMAINS)


# --------------------
# Built-in detectors
# -------------------


# Inside-PEM helpers: distinguish a true full block (with body) from a
# match where header and footer happen to be adjacent in the string
# pool but the body lives elsewhere (split-at-runtime case).
_PEM_HEADER_RE = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
)
_PEM_FOOTER_RE = re.compile(
    r"-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
)
# Base64-ish line of at least 60 chars — typical PEM body wraps at 64.
_PEM_BODY_LINE_RE = re.compile(r"^[A-Za-z0-9+/=]{60,}$", re.MULTILINE)
# Minimum non-whitespace base64 chars between BEGIN/END to call it a
# "real" body. EC P-256 PEM body ~ 150 chars; we set the floor at 100
# to give some margin.
_PEM_BODY_MIN_CHARS = 100


def _classify_pem_match(value: str) -> tuple:
    """Inspect a regex match for ``BEGIN..END`` and return (kind, body_len).

    ``kind`` is one of:

    * ``"full"``  — body has enough base64 material to be a real key
    * ``"split"`` — header and footer adjacent, body absent or tiny
                    (the body is likely concatenated at runtime from
                    other strings in the same DEX/asset)
    """
    inner = _PEM_HEADER_RE.sub("", value, count=1)
    inner = _PEM_FOOTER_RE.sub("", inner, count=1)
    # Count only base64 characters so whitespace and stray content
    # don't lift a body-less match above the floor.
    body_chars = sum(1 for c in inner if c.isalnum() or c in "+/=")
    if body_chars >= _PEM_BODY_MIN_CHARS:
        return "full", body_chars
    return "split", body_chars


@register
class SecretDetector(Detector):
    """Vendor-specific high-signal patterns + heuristic key=value matching."""

    name = "secrets"
    category = "secret"

    # Compile patterns once at class load. _COMPILED is an attribute so
    # subclasses can extend or replace it.
    _COMPILED = [
        (rule, re.compile(pat), conf, cat, desc)
        for rule, pat, conf, cat, desc in SECRET_PATTERNS
    ]
    _COMPILED_HEUR = [
        (rule, re.compile(pat), conf, cat, desc)
        for rule, pat, conf, cat, desc in HEURISTIC_PATTERNS
    ]

    def scan_text(self, text, source, apk):
        # Track sources where we already emitted a full PEM block so we
        # can suppress the noisy "header-only" fallback finding for the
        # same key — the full block already carries the same intel at
        # higher confidence.
        full_pem_seen = False

        for rule, regex, conf, cat, desc in self._COMPILED:
            for m in regex.finditer(text):
                value = m.group(0)

                # PEM post-processing: the full-block regex is greedy
                # enough to span over header+footer pairs that are only
                # adjacent in the string pool (no body in between). We
                # detect that here and downgrade to a "split" finding
                # instead of pretending we recovered a key.
                if rule == "private_key_pem":
                    kind, body_chars = _classify_pem_match(value)
                    if kind == "split":
                        # Surface the discovery with honest framing.
                        body_hits = len(_PEM_BODY_LINE_RE.findall(text))
                        hint = (
                            f"BEGIN/END markers adjacent but body has only "
                            f"{body_chars} base64 chars (need ≥{_PEM_BODY_MIN_CHARS}). "
                            f"Found {body_hits} candidate base64 line(s) elsewhere "
                            f"in this source — body is likely concatenated at "
                            f"runtime from separate string-pool entries."
                        )
                        yield Finding(
                            type="private_key_pem_split",
                            value=_truncate(value, maxlen=400),
                            source=source,
                            apk=apk,
                            confidence=0.80,
                            category="secret",
                            description=hint,
                        )
                        # Important: don't set full_pem_seen, so that
                        # the orphan-header detector still fires with
                        # the additional context it carries.
                        continue
                    full_pem_seen = True

                if rule == "private_key_pem_header" and full_pem_seen:
                    continue

                maxlen = _VALUE_MAXLEN_OVERRIDES.get(rule, 200)
                yield Finding(
                    type=rule,
                    value=_truncate(value, maxlen=maxlen),
                    source=source,
                    apk=apk,
                    confidence=conf,
                    category=cat,
                    description=desc,
                )

        for rule, regex, conf, cat, desc in self._COMPILED_HEUR:
            for m in regex.finditer(text):
                # Group 2 is the value; group 1 is the key name.
                value = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
                if _looks_like_placeholder(value):
                    continue
                # Entropy gate: long values that read like English (low
                # entropy) are almost always false positives. We only
                # apply it to the generic high_entropy_blob rule and to
                # any heuristic value >= 20 chars, where the noise is
                # highest. Vendor patterns above are unaffected.
                if rule == "high_entropy_blob" or len(value) >= 20:
                    ent = _shannon_entropy(value)
                    if ent < 3.5:
                        continue
                key_name = (m.group(1) if m.lastindex else "").lower()
                # Show the key=value pair so the user knows the context.
                shown = f"{key_name}={value}" if key_name else value
                yield Finding(
                    type=rule,
                    value=_truncate(shown),
                    source=source,
                    apk=apk,
                    confidence=conf,
                    category=cat,
                    description=desc,
                )


@register
class EmailDetector(Detector):
    name = "emails"
    category = "secret"

    def scan_text(self, text, source, apk):
        for m in EMAIL_RE.finditer(text):
            value = m.group(0)
            if _is_noise_email(value):
                continue
            yield Finding(
                type="email",
                value=value,
                source=source,
                apk=apk,
                confidence=0.5,
                category="secret",
                description="Email address (may be a developer/support contact)",
            )


@register
class UrlDetector(Detector):
    """Extract HTTP(S) URLs and flag internal/private endpoints."""

    name = "urls"
    category = "url"

    # Trailing characters frequently captured by the greedy URL regex but
    # that are usually punctuation from surrounding text/code.
    _STRIP = ".,;:)\"'>}]"

    def scan_text(self, text, source, apk):
        # Per-call dedup so a single very chatty file doesn't repeat the
        # same URL hundreds of times before global dedup runs.
        seen: set = set()
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(self._STRIP)
            if not url or url in seen:
                continue
            seen.add(url)
            if URL_NOISE_RE.search(url):
                continue
            internal = bool(INTERNAL_HOST_RE.search(url))
            yield Finding(
                type="internal_endpoint" if internal else "url",
                value=_truncate(url),
                source=source,
                apk=apk,
                confidence=0.85 if internal else 0.7,
                category="url",
                description=("Internal/private endpoint reachable from the app"
                             if internal else "External URL referenced by the app"),
            )


@register
class BareIPDetector(Detector):
    """Standalone IPv4 addresses (with optional :port).

    The regular :class:`UrlDetector` requires an ``http(s)://`` scheme,
    which misses the way malware and reverse-shell payloads usually
    embed their C2: as a plain literal like ``192.168.1.5`` passed
    directly to ``new Socket(host, port)``. This detector picks those
    up and classifies them by RFC1918/loopback/link-local membership.
    """

    name = "bare_ip"
    category = "url"

    def scan_text(self, text, source, apk):
        # Two-pass approach: first collect all (ip, port) tuples so we
        # can suppress redundant findings (e.g. don't emit both
        # "192.168.1.5" and "192.168.1.5:443" for the same host — the
        # version-with-port is strictly more informative).
        hits: dict = {}  # ip -> set of ports (None for bare ip)
        for m in BARE_IPV4_RE.finditer(text):
            ip = m.group(1)
            port = m.group(2)
            if _NOISE_IP_RE.match(ip) or ip.startswith("0."):
                continue
            hits.setdefault(ip, set()).add(port)

        for ip, ports in hits.items():
            # If both bare and ":port" forms exist for the same IP,
            # drop the bare one — it's covered by the more specific
            # finding and would just be noise.
            if len(ports) > 1 and None in ports:
                ports.discard(None)

            for port in ports:
                display = f"{ip}:{port}" if port else ip
                is_private = bool(_PRIVATE_IP_RE.match(ip))

                if ip.startswith("127."):
                    conf = 0.55
                    desc = "Loopback IP literal — likely debug/testing leftover"
                    ftype = "bare_ip_loopback"
                elif is_private and port:
                    conf = 0.90
                    desc = (f"Private/internal IP with explicit port "
                            f"({display}). Strong indicator of a "
                            f"reverse-shell / C2 / staging endpoint embedded "
                            f"in the APK.")
                    ftype = "bare_ip_private_with_port"
                elif is_private:
                    conf = 0.80
                    desc = (f"Private/internal IP literal ({ip}). Should not "
                            f"normally ship in a release build; common in "
                            f"malware payloads (msfvenom reverse_tcp/https).")
                    ftype = "bare_ip_private"
                elif port and 1 <= int(port) <= 65535:
                    conf = 0.65
                    desc = (f"Public IP with explicit port ({display}). "
                            f"Could be a hardcoded C2 host, a backend by "
                            f"IP, or staging.")
                    ftype = "bare_ip_public_with_port"
                else:
                    conf = 0.50
                    desc = ("Public IPv4 literal (no port). Often legitimate "
                            "(CDN, fallback) but worth verifying.")
                    ftype = "bare_ip_public"

                yield Finding(
                    type=ftype,
                    value=display,
                    source=source,
                    apk=apk,
                    confidence=conf,
                    category="url",
                    description=desc,
                )


@register
class MalwareSignatureDetector(Detector):
    """Strings that strongly indicate the APK is a known payload / RAT.

    These are package and method names that survive across stager
    versions because the runtime needs to resolve them. Hits here
    almost always mean the APK is malicious or generated by an
    offensive-security tool (msfvenom, AhMyth, etc.).
    """

    name = "malware_signatures"
    category = "secret"

    _COMPILED = [
        (rule, re.compile(pat, re.IGNORECASE), conf, cat, desc)
        for rule, pat, conf, cat, desc in MALWARE_SIGNATURE_PATTERNS
    ]

    def scan_text(self, text, source, apk):
        seen: set = set()
        for rule, regex, conf, cat, desc in self._COMPILED:
            for m in regex.finditer(text):
                value = m.group(0)
                key = (rule, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    type=rule,
                    value=value,
                    source=source,
                    apk=apk,
                    confidence=conf,
                    category=cat,
                    description=desc,
                )


@register
class TrustManagerBypassDetector(Detector):
    """Detect insecure ``TrustManager`` / ``HostnameVerifier`` patterns.

    A ``TrustManager`` whose ``checkServerTrusted`` is empty (or that
    returns ``null`` from ``getAcceptedIssuers``) accepts any TLS
    certificate. A ``HostnameVerifier`` that always returns true
    accepts any host. Both are full-MitM bugs.

    We can't see Java method bodies — we only see method *names* in
    the DEX string table. So this detector fires on the **co-occurrence
    pattern**: when an APK contains the names of all the methods you'd
    need to roll your own permissive trust manager, it's almost
    certainly doing exactly that. msfvenom payloads are a textbook
    case (they accept any HTTPS cert from the C2).
    """

    name = "trust_bypass"
    category = "secret"

    # Each signature is a set of strings that must ALL be present in
    # the same source for the finding to fire. False positives are
    # very rare with this co-occurrence approach.
    _SIGNATURES = [
        ({"checkServerTrusted", "getAcceptedIssuers", "X509TrustManager"},
         "custom_trustmanager",
         "Custom X509TrustManager implementation present. Combined "
         "with empty checkServerTrusted bodies (which we can't verify "
         "statically), this accepts ANY TLS certificate — full MitM. "
         "Confirm by inspecting the class with jadx."),
        ({"setHostnameVerifier", "HostnameVerifier", "verify"},
         "custom_hostnameverifier",
         "Custom HostnameVerifier installed via setHostnameVerifier. "
         "If verify() returns true unconditionally (common pattern), "
         "TLS hostname validation is disabled."),
        ({"setSSLSocketFactory", "X509TrustManager", "SSLContext"},
         "custom_sslcontext",
         "Custom SSLContext + TrustManager wired into HttpsURLConnection "
         "via setSSLSocketFactory. Strongly suggests cert pinning is "
         "either bypassed or being implemented manually (often badly)."),
    ]

    def scan_text(self, text, source, apk):
        for needles, ftype, desc in self._SIGNATURES:
            if all(n in text for n in needles):
                yield Finding(
                    type=f"trustmanager_{ftype}",
                    value=", ".join(sorted(needles)),
                    source=source,
                    apk=apk,
                    confidence=0.85,
                    category="secret",
                    description=desc,
                )


@register
class DynamicCodeLoadingDetector(Detector):
    """Flag stager-style runtime code loading.

    ``DexClassLoader`` + ``loadClass`` + ``getMethod.invoke`` is *the*
    pattern for a two-stage payload: the APK on disk is small and
    benign, the real malware is downloaded and reflected into the
    process at runtime. Legitimate apps almost never need this; when
    they do (plugin systems, A/B testing frameworks) they usually use
    higher-level libs that don't put these exact strings together.
    """

    name = "dynamic_load"
    category = "secret"

    _STAGER_NEEDLES = ("DexClassLoader", "loadClass", "invoke")

    def scan_text(self, text, source, apk):
        if all(n in text for n in self._STAGER_NEEDLES):
            yield Finding(
                type="dynamic_dex_loading",
                value="DexClassLoader + loadClass + invoke",
                source=source,
                apk=apk,
                confidence=0.85,
                category="secret",
                description=(
                    "Runtime DEX loading via reflection. Hallmark of a "
                    "stager / dropper / second-stage payload pattern. "
                    "The APK on disk is unlikely to be the full malware — "
                    "the real code is fetched at runtime."
                ),
            )


@register
class DebugCertificateDetector(Detector):
    """Detect ``META-INF/*.RSA`` signed with the Android debug key.

    The default Android debug keystore subject is
    ``CN=Android Debug, O=Android, C=US``. An APK signed with this
    key has bypassed the release-signing step entirely — it should
    never reach a Play Store / production audience. Common in
    msfvenom output, leaked test builds, and supply-chain mistakes.

    We don't parse X.509 — we just look for the well-known subject
    string in the binary scan of the cert file.
    """

    name = "debug_cert"
    category = "misconfig"

    _DEBUG_SUBJECT_PATTERNS = (
        b"CN=Android Debug",
        b"O=Android, C=US",
    )

    def scan_text(self, text, source, apk):
        # We only run on META-INF cert files. Other text might
        # legitimately mention "Android Debug" (e.g. log strings).
        sl = source.lower()
        if not (sl.endswith(".rsa") or sl.endswith(".dsa") or sl.endswith(".ec")):
            return
        if "META-INF/" not in source:
            return
        if "CN=Android Debug" in text:
            yield Finding(
                type="debug_signing_certificate",
                value="CN=Android Debug, O=Android, C=US",
                source=source,
                apk=apk,
                confidence=0.95,
                category="misconfig",
                description=(
                    "APK signed with the Android debug keystore. This "
                    "is the default key Android Studio uses for local "
                    "builds — it must NEVER reach production. Indicates "
                    "either a leaked dev build, a malware sample (msfvenom "
                    "default), or a broken release pipeline."
                ),
            )


# IPv4 octets encoded as a 4-byte sequence in DEX bytecode operands.
# msfvenom does NOT put the LHOST in the string table — it lives as
# 4 individual `const/16` instructions. We scan the raw DEX bytes
# (not just string_ids) for the pattern: 4 plausible IPv4 octets in a
# row, with at least one in RFC1918 / loopback / link-local space.
class _DexBytecodeIPDetector:
    """Internal helper, not registered; called from the scanner.

    Recovers IPv4 addresses that don't appear in the DEX string pool.
    msfvenom and similar payloads load LHOST as separate small-integer
    operands rather than as a String, so the IP is **never** in the
    string_ids table — only in the bytecode operands.

    Strategy: anchor the search on the 2-byte network prefix of each
    private RFC1918 / loopback / link-local block (e.g. ``\\xc0\\xa8``
    for 192.168.0.0/16), then verify the next two bytes form a valid
    private IPv4 in one of three layouts:

    * **contiguous quartet** — 4 bytes in a row (byte arrays, struct
      literals, primitive-array initialisers)
    * **stride-2** — each octet followed by a single zero byte (the
      const/16 dalvik opcode immediates)
    * **stride-4** — each octet followed by three zero bytes (the
      ``const`` 32-bit-immediate opcode)

    Anchoring on the prefix means we use ``bytes.find()`` (C-speed)
    to skip 99% of the file and only do Python work where it might
    pay off. Random byte data on a 5 MB DEX completes in <50ms with
    near-zero false positives.
    """

    # Cap: even with strong filtering, refuse to emit more than this
    # many IPs per source. Anything over this is almost certainly
    # noise from a huge DEX and would just flood the report.
    _MAX_HITS_PER_SOURCE = 5

    @classmethod
    def scan_bytes(cls, data: bytes, source: str, apk: str) -> Iterator[Finding]:
        n = len(data)
        seen: set = set()
        emitted = 0

        def _verify_and_make(o1, o2, o3, o4, mode):
            """Last-line plausibility check before emitting."""
            if 0 in (o3, o4) or 255 in (o3, o4):
                return None
            if o1 == o2 == o3 == o4:
                return None
            ip = f"{o1}.{o2}.{o3}.{o4}"
            if ip in seen:
                return None
            if not _PRIVATE_IP_RE.match(ip):
                return None
            if _NOISE_IP_RE.match(ip):
                return None
            seen.add(ip)
            return Finding(
                type="bare_ip_private_dex_bytecode",
                value=ip,
                source=source,
                apk=apk,
                confidence=0.65,
                category="url",
                description=(
                    f"Possible private IPv4 ({ip}) recovered from raw DEX "
                    f"bytes (pattern: {mode}). Common when the LHOST of a "
                    f"reverse-shell / C2 stager is loaded as separate "
                    f"integer operands rather than as a String — invisible "
                    f"to string-table scans. Heuristic: verify by "
                    f"disassembling the DEX (jadx, baksmali)."
                ),
            )

        # ---- Pattern 1: contiguous quartet (e.g. byte[] = {...}) ---------
        # Anchor on 2-byte network prefixes for high-precision ranges.
        # We deliberately skip the bare 10.x prefix here — too noisy as
        # a single-byte signature on random data.
        contig_prefixes = [bytes([192, 168]), bytes([169, 254])] + \
                          [bytes([172, x]) for x in range(16, 32)]
        for prefix in contig_prefixes:
            start = 0
            while True:
                pos = data.find(prefix, start)
                if pos < 0:
                    break
                start = pos + 1
                if pos + 4 <= n:
                    f = _verify_and_make(
                        data[pos], data[pos+1], data[pos+2], data[pos+3],
                        "contiguous quartet")
                    if f:
                        yield f
                        emitted += 1
                        if emitted >= cls._MAX_HITS_PER_SOURCE:
                            return

        # ---- Pattern 2: stride-2 (const/16 operand stream) ---------------
        # Anchor on the 4-byte signature (octet1, 0, octet2, 0) for the
        # specific network: e.g. [192, 0, 168, 0] for 192.168/16.
        stride2_anchors = [
            bytes([192, 0, 168, 0]),
            bytes([169, 0, 254, 0]),
        ] + [bytes([172, 0, x, 0]) for x in range(16, 32)]
        for anchor in stride2_anchors:
            start = 0
            while True:
                pos = data.find(anchor, start)
                if pos < 0:
                    break
                start = pos + 1
                # Need the next 4 bytes for octets 3 and 4 (each + zero)
                if (pos + 8 <= n and data[pos+5] == 0 and data[pos+7] == 0):
                    f = _verify_and_make(
                        data[pos], data[pos+2], data[pos+4], data[pos+6],
                        "stride-2 (const/16 immediates)")
                    if f:
                        yield f
                        emitted += 1
                        if emitted >= cls._MAX_HITS_PER_SOURCE:
                            return

        # ---- Pattern 4: stride-4 with opcode in between ------------------
        # Real msfvenom output: 4 consecutive `const/16 vR, #+OCTET` where
        # each instruction is 4 bytes laid out [0x13 vR OCT 0x00], so the
        # octets sit at offsets 2, 6, 10, 14 of the run with arbitrary
        # opcode/reg bytes in between. We anchor on a single octet/zero
        # pair (e.g. `bytes([192, 0])`) and check that the bytes 4, 8, 12
        # bytes later are also (octet, 0) for octets that would form
        # a private IPv4.
        for first_octet in (192, 169) + tuple(range(172, 188)):
            anchor = bytes([first_octet, 0])
            start = 0
            while True:
                pos = data.find(anchor, start)
                if pos < 0:
                    break
                start = pos + 1
                if pos + 14 < n:
                    # Check that the (octet, 0) pattern repeats at +4, +8, +12
                    if data[pos+5] == 0 and data[pos+9] == 0 and data[pos+13] == 0:
                        f = _verify_and_make(
                            data[pos], data[pos+4], data[pos+8], data[pos+12],
                            "stride-4 with intermediate opcode bytes "
                            "(typical msfvenom const/16 sequence)")
                        if f:
                            yield f
                            emitted += 1
                            if emitted >= cls._MAX_HITS_PER_SOURCE:
                                return




@register
class ManifestDetector(Detector):
    """Misconfiguration checks against parsed AndroidManifest.xml elements."""

    name = "manifest"
    category = "misconfig"

    def scan_manifest(self, elements, source, apk):
        for el in elements:
            yield from self._check_element(el, source, apk)

    @staticmethod
    def _check_element(el, source: str, apk: str) -> Iterator[Finding]:
        n = el.name
        a = el.attrs

        if n == "application":
            if a.get("android:debuggable", "").lower() == "true":
                yield Finding(
                    type="manifest_debuggable",
                    value='android:debuggable="true"',
                    source=source,
                    apk=apk,
                    confidence=0.99,
                    category="misconfig",
                    description=(
                        "<application android:debuggable=\"true\"> lets any user "
                        "with adb attach a debugger and dump app memory."
                    ),
                )
            if a.get("android:allowBackup", "").lower() == "true":
                yield Finding(
                    type="manifest_allow_backup",
                    value='android:allowBackup="true"',
                    source=source,
                    apk=apk,
                    confidence=0.6,
                    category="misconfig",
                    description=(
                        "android:allowBackup=\"true\" allows ADB backup and "
                        "exfiltration of private app data."
                    ),
                )
            if a.get("android:usesCleartextTraffic", "").lower() == "true":
                yield Finding(
                    type="manifest_cleartext_traffic",
                    value='android:usesCleartextTraffic="true"',
                    source=source,
                    apk=apk,
                    confidence=0.95,
                    category="misconfig",
                    description=(
                        "Cleartext (HTTP) traffic is explicitly permitted; "
                        "credentials and tokens may travel unencrypted."
                    ),
                )
            nsc = a.get("android:networkSecurityConfig")
            if nsc:
                yield Finding(
                    type="manifest_network_security_config",
                    value=f"networkSecurityConfig={nsc}",
                    source=source,
                    apk=apk,
                    confidence=0.4,
                    category="misconfig",
                    description=(
                        "Custom network security config in use; review the "
                        "referenced XML for cleartext-permitted domains and "
                        "trust-anchor overrides."
                    ),
                )

        if n in ("activity", "activity-alias", "service", "receiver", "provider"):
            exported = a.get("android:exported", "").lower()
            permission = a.get("android:permission")
            comp_name = a.get("android:name", "?")

            # Pre-Android 12 the default for components with intent filters
            # was implicitly "true". We only flag the explicit case here to
            # keep noise low; the user can review components manually.
            if exported == "true" and not permission:
                yield Finding(
                    type=f"manifest_exported_{n}",
                    value=(
                        f'<{n} android:name="{comp_name}" '
                        f'android:exported="true">'
                    ),
                    source=source,
                    apk=apk,
                    confidence=0.85,
                    category="misconfig",
                    description=(
                        f"{n.capitalize()} is exported with no permission, "
                        f"so any installed app can invoke it via IPC."
                    ),
                )
            # Content provider with grantUriPermissions is usually a smell.
            if n == "provider" and a.get("android:grantUriPermissions", "").lower() == "true":
                yield Finding(
                    type="manifest_provider_grant_uri",
                    value=f'<provider android:name="{comp_name}" grantUriPermissions="true">',
                    source=source,
                    apk=apk,
                    confidence=0.6,
                    category="misconfig",
                    description=(
                        "ContentProvider grants ad-hoc URI permissions; verify "
                        "path-permission scoping is correct."
                    ),
                )
