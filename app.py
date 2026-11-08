
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import time
from difflib import SequenceMatcher
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import certifi
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "sentinel.db")))
MAX_SCAN_SECONDS = int(os.getenv("MAX_SCAN_SECONDS", "12"))
CA_BUNDLE = certifi.where()

app = FastAPI(
    title="SENTINEL X",
    version="0.1.0",
    description="Unified web trust and threat intelligence prototype"
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


# ============================================================
# REQUEST MODELS
# ============================================================

class ScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url_shape(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Enter a website URL")

        if not re.match(r"^https?://", value, re.I):
            value = "https://" + value

        parsed = urlparse(value)

        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Enter a valid public website URL")

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported")

        return value


class ReportRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    category: str = Field(default="phishing", max_length=40)
    details: str = Field(default="", max_length=500)


class ThreatDNARequest(BaseModel):
    domain: str = Field(min_length=3, max_length=2048)


# ============================================================
# DATABASE
# ============================================================

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                normalized_host TEXT NOT NULL,
                category TEXT NOT NULL,
                details TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'community-reported',
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        report_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(reports)"
            ).fetchall()
        }

        if "submission_count" not in report_columns:
            conn.execute("""
                ALTER TABLE reports
                ADD COLUMN submission_count INTEGER NOT NULL DEFAULT 1
            """)

        if "last_reported_at" not in report_columns:
            conn.execute("""
                ALTER TABLE reports
                ADD COLUMN last_reported_at TEXT
            """)

        conn.execute("""
            UPDATE reports
            SET last_reported_at = created_at
            WHERE last_reported_at IS NULL
        """)

        # Keep the newest record for each hostname/category pair.
        conn.execute("""
            DELETE FROM reports
            WHERE id NOT IN (
                SELECT MAX(id)
                FROM reports
                GROUP BY normalized_host, category
            )
        """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_reports_host_category
            ON reports(normalized_host, category)
        """)


@app.on_event("startup")
def startup() -> None:
    init_db()


# ============================================================
# URL AND NETWORK SAFETY
# ============================================================

def normalize_url(raw: str) -> str:
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    netloc = host

    if parsed.port:
        netloc += f":{parsed.port}"

    path = parsed.path or "/"

    return urlunparse((
        parsed.scheme.lower(),
        netloc,
        path,
        "",
        parsed.query,
        ""
    ))


def resolve_public_host(host: str, port: int = 443) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]

    except ValueError:
        try:
            records = socket.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM
            )
            addresses = sorted({record[4][0] for record in records})

        except socket.gaierror:
            raise ValueError("The domain could not be resolved")

    if not addresses:
        raise ValueError("The domain has no usable IP address")

    for address in addresses:
        ip = ipaddress.ip_address(address)

        if not ip.is_global:
            raise ValueError(
                "Scanning private, local, or reserved network addresses is blocked"
            )

    return addresses


def safe_fetch(
    url: str
) -> tuple[httpx.Response | None, str, list[str]]:
    """Fetch a public URL with bounded redirects and public-address checks."""

    current = url
    redirect_chain: list[str] = []
    deadline = time.monotonic() + MAX_SCAN_SECONDS

    headers = {
        "User-Agent": "SentinelX-Hackathon-Prototype/0.1 (+website trust assessment)"
    }

    with httpx.Client(
        timeout=4.0,
        follow_redirects=False,
        verify=CA_BUNDLE,
        trust_env=False,
        headers=headers
    ) as client:

        for _ in range(5):
            if time.monotonic() > deadline:
                break

            parsed = urlparse(current)
            host = parsed.hostname or ""
            port = parsed.port or (
                443 if parsed.scheme == "https" else 80
            )

            resolve_public_host(host, port)

            try:
                response = client.get(current)

            except (httpx.HTTPError, ssl.SSLError):
                return None, current, redirect_chain

            if response.status_code not in (301, 302, 303, 307, 308):
                return response, current, redirect_chain

            location = response.headers.get("location")

            if not location:
                return response, current, redirect_chain

            redirect_chain.append(current)
            current = str(response.url.join(location))

            if urlparse(current).scheme not in ("http", "https"):
                raise ValueError(
                    "A redirect to a non-web protocol was blocked"
                )

        return None, current, redirect_chain


# ============================================================
# TLS CERTIFICATE INTELLIGENCE
# ============================================================

def certificate_check(host: str, port: int = 443) -> dict[str, Any]:

    result: dict[str, Any] = {
        "checked": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "hostname_match": False,
        "error": None
    }

    try:
        addresses = resolve_public_host(host, port)
        context = ssl.create_default_context(cafile=CA_BUNDLE)

        last_error: Exception | None = None
        cert = None

        for address in addresses:
            try:
                raw = socket.create_connection(
                    (address, port),
                    timeout=3
                )

                with context.wrap_socket(
                    raw,
                    server_hostname=host
                ) as tls:

                    cert = tls.getpeercert()
                    result["tls_version"] = tls.version()
                    result["cipher"] = (
                        tls.cipher()[0] if tls.cipher() else None
                    )

                break

            except Exception as exc:
                last_error = exc

        if cert is None:
            raise last_error or RuntimeError(
                "Certificate connection failed"
            )

        result["checked"] = True
        result["valid"] = True

        result["issuer"] = ", ".join(
            f"{key}={value}"
            for group in cert.get("issuer", [])
            for key, value in group
        )

        result["subject"] = ", ".join(
            f"{key}={value}"
            for group in cert.get("subject", [])
            for key, value in group
        )

        result["not_before"] = cert.get("notBefore")
        result["not_after"] = cert.get("notAfter")

        sans = [
            value
            for kind, value in cert.get("subjectAltName", [])
            if kind == "DNS"
        ]

        result["san_count"] = len(sans)

        if cert.get("notAfter"):
            expiry = datetime.strptime(
                cert["notAfter"],
                "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            result["days_remaining"] = (
                expiry - datetime.now(timezone.utc)
            ).days

        result["hostname_match"] = True

    except ssl.SSLCertVerificationError as exc:
        result["checked"] = True
        result["valid"] = False
        result["failure_kind"] = "certificate_validation"
        result["error"] = str(exc)[:220]

    except Exception as exc:
        result["failure_kind"] = "inspection_unavailable"
        result["error"] = str(exc)[:220]

    return result


# ============================================================
# URL HEURISTICS AND BRAND INTELLIGENCE
# ============================================================

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".top", ".xyz", ".click",
    ".work", ".country", ".gq", ".tk"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "secure", "account", "update",
    "wallet", "banking", "password", "signin", "support",
    "payment", "invoice", "bonus", "free"
}

BRANDS = {
    "google", "microsoft", "apple", "amazon", "paypal",
    "facebook", "instagram", "netflix", "sbi", "hdfc",
    "icici", "tcs"
}

TRUSTED_BRAND_DOMAINS = {
    "google": ("google.com", "google.co.in"),
    "microsoft": (
        "microsoft.com", "live.com", "office.com",
        "microsoftonline.com"
    ),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.in"),
    "paypal": ("paypal.com",),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "netflix": ("netflix.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "tcs": ("tcs.com",),
}


def is_trusted_brand_domain(host: str, brand: str) -> bool:
    return any(
        host == domain or host.endswith("." + domain)
        for domain in TRUSTED_BRAND_DOMAINS.get(brand, ())
    )


def url_analysis(
    url: str,
    host: str
) -> tuple[int, list[dict[str, str]]]:

    parsed = urlparse(url)
    findings: list[dict[str, str]] = []
    score = 0

    if parsed.scheme != "https":
        score += 12
        findings.append({
            "severity": "medium",
            "title": "Connection is not HTTPS",
            "detail": (
                "The submitted URL uses HTTP, so transport "
                "encryption is not established."
            )
        })

    if len(url) > 100:
        score += 7
        findings.append({
            "severity": "low",
            "title": "Unusually long URL",
            "detail": (
                "Long URLs can obscure the true destination, "
                "although length alone is not proof of phishing."
            )
        })

    if "@" in parsed.netloc:
        score += 15
        findings.append({
            "severity": "high",
            "title": "At-sign in URL authority",
            "detail": (
                "The URL contains user-info syntax that can "
                "disguise the actual destination."
            )
        })

    if host.count("-") >= 3:
        score += 8
        findings.append({
            "severity": "low",
            "title": "Hyphen-heavy domain",
            "detail": "Multiple hyphens can be used in deceptive domain names."
        })

    if host.startswith("xn--") or ".xn--" in host:
        score += 15
        findings.append({
            "severity": "medium",
            "title": "Internationalized domain encoding",
            "detail": (
                "Punycode can represent legitimate international "
                "domains but may also be used in lookalike attacks."
            )
        })

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 8
        findings.append({
            "severity": "low",
            "title": "TLD merits additional scrutiny",
            "detail": (
                "This top-level domain appears in a heuristic "
                "watchlist; this is not proof of maliciousness."
            )
        })

    labels = set(re.split(r"[.-]", host))
    hits = sorted(labels & SUSPICIOUS_WORDS)

    if hits:
        score += min(12, 4 + 2 * len(hits))
        findings.append({
            "severity": "low",
            "title": "Sensitive-action keywords in domain",
            "detail": "Domain labels contain: " + ", ".join(hits) + "."
        })

    brand_hits = sorted(
        brand for brand in BRANDS
        if brand in host and not is_trusted_brand_domain(host, brand)
    )

    if brand_hits:
        score += 18
        findings.append({
            "severity": "high",
            "title": "Possible brand-name impersonation",
            "detail": (
                "Brand terms appear in the hostname: "
                + ", ".join(brand_hits)
                + ". Manual verification is required."
            )
        })

    if len(host.split(".")) > 4:
        score += 6
        findings.append({
            "severity": "low",
            "title": "Many domain subdomains",
            "detail": (
                "The hostname has several labels; inspect "
                "the registered domain carefully."
            )
        })

    return min(score, 65), findings


# ============================================================
# SECURITY HEADER ANALYSIS
# ============================================================

def header_analysis(
    response: httpx.Response | None
) -> tuple[int, list[dict[str, str]], dict[str, bool]]:

    if response is None:
        return 0, [{
            "severity": "info",
            "title": "HTTP inspection unavailable",
            "detail": (
                "The site did not return a response within "
                "the scan limits."
            )
        }], {}

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    checks = {
        "Strict-Transport-Security": "strict-transport-security",
        "Content-Security-Policy": "content-security-policy",
        "X-Content-Type-Options": "x-content-type-options",
        "X-Frame-Options": "x-frame-options",
        "Referrer-Policy": "referrer-policy",
    }

    status = {
        label: key in headers
        for label, key in checks.items()
    }

    if response.status_code in (401, 403, 429, 503):
        findings = [{
            "severity": "info",
            "title": "Limited security-header assessment",
            "detail": (
                f"The website returned HTTP {response.status_code}; "
                "this response may be generated by an access-control "
                "or edge layer, so missing headers are not scored "
                "as application weaknesses."
            )
        }]

        return 0, findings, status

    missing = [
        label
        for label, key in checks.items()
        if key not in headers
    ]

    findings = [
        {
            "severity": "low",
            "title": f"Missing {name}",
            "detail": (
                f"The response does not include the {name} header. "
                "This is a hardening observation, not evidence "
                "of phishing by itself."
            )
        }
        for name in missing
    ]

    return min(len(missing), 5), findings, status


# ============================================================
# COMMUNITY INTELLIGENCE
# ============================================================

def community_matches(host: str) -> list[dict[str, Any]]:

    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, url, category, details, status, created_at,
                   submission_count, last_reported_at
            FROM reports
            WHERE normalized_host = ?
            ORDER BY id DESC LIMIT 10
            """,
            (host,)
        ).fetchall()

    return [dict(row) for row in rows]


# ============================================================
# THREAT DNA - DOMAIN SIMILARITY INTELLIGENCE
# ============================================================

THREAT_NOISE_WORDS = {
    "www", "login", "signin", "secure", "verify",
    "account", "support", "online", "update",
    "payment", "service", "portal"
}

MULTI_PART_SUFFIXES = {
    "co.in", "com.in", "net.in", "org.in", "ac.in",
    "gov.in", "nic.in", "co.uk", "org.uk", "com.au"
}


def normalize_domain_text(value: str) -> str:
    """Normalize common visual substitutions in domain labels."""

    return (
        value.lower()
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("7", "t")
        .replace("8", "b")
    )


def domain_core(host: str) -> str:
    """Extract an approximate registered-domain label."""

    labels = host.lower().rstrip(".").split(".")

    if len(labels) <= 1:
        return labels[0]

    suffix = ".".join(labels[-2:])

    if suffix in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return labels[-3]

    return labels[-2]


def domain_tokens(host: str) -> list[str]:
    """Extract meaningful hostname labels for brand comparison."""

    tokens = []

    for label in host.lower().rstrip(".").split(".")[:-1]:
        for token in label.split("-"):
            if token and token not in THREAT_NOISE_WORDS:
                tokens.append(normalize_domain_text(token))

    return tokens


def threat_dna_analysis(host: str) -> dict[str, Any]:
    """
    Analyze a hostname without DNS or HTTP requests.

    Exact community matches are identified separately from
    similar-domain matches.
    """

    host = host.lower().rstrip(".")
    tokens = domain_tokens(host)

    # --------------------------------------------------------
    # 1. Detect potential brand impersonation.
    # --------------------------------------------------------

    brand_matches = []

    for brand in sorted(BRANDS):

        if is_trusted_brand_domain(host, brand):
            continue

        best_token = None
        best_similarity = 0.0

        for token in tokens:
            similarity = SequenceMatcher(
                None,
                token,
                brand
            ).ratio()

            threshold = 1.0 if len(brand) <= 3 else 0.78

            if similarity >= threshold and similarity > best_similarity:
                best_token = token
                best_similarity = similarity

        if best_token is not None:
            brand_matches.append({
                "brand": brand,
                "matched_label": best_token,
                "similarity": round(best_similarity, 2),
                "evidence": (
                    f"The hostname contains a domain label similar "
                    f"to the brand name '{brand}'."
                )
            })

    # --------------------------------------------------------
    # 2. Compare against community-reported domains.
    # --------------------------------------------------------

    current_core = domain_core(host)
    normalized_core = normalize_domain_text(current_core)

    with db() as conn:
        rows = conn.execute(
            """
            SELECT normalized_host, category, status, created_at,
                   submission_count, last_reported_at
            FROM reports
            ORDER BY id DESC LIMIT 200
            """
        ).fetchall()

    exact_matches = []
    similar_matches = []

    for row in rows:
        reported_host = row["normalized_host"].lower().rstrip(".")

        # Exact hostname match: do not skip it.
        if reported_host == host:
            exact_matches.append({
                "host": reported_host,
                "category": row["category"],
                "status": row["status"],
                "similarity": 1.0,
                "match_type": "exact",
                "created_at": row["created_at"],
                "submission_count": row["submission_count"],
                "last_reported_at": row["last_reported_at"],
                "evidence": (
                    "This exact hostname has previously been "
                    "submitted to community intelligence. "
                    "The community report is unverified."
                )
            })
            continue

        reported_core = domain_core(reported_host)

        # Skip different subdomains of the same approximate
        # registered-domain label.
        if reported_core == current_core:
            continue

        other_core = normalize_domain_text(reported_core)

        if min(len(normalized_core), len(other_core)) < 5:
            continue

        similarity = SequenceMatcher(
            None,
            normalized_core,
            other_core
        ).ratio()

        if similarity >= 0.78:
            similar_matches.append({
                "host": reported_host,
                "category": row["category"],
                "status": row["status"],
                "similarity": round(similarity, 2),
                "match_type": "similar",
                "created_at": row["created_at"],
                "submission_count": row["submission_count"],
                "last_reported_at": row["last_reported_at"],
                "evidence": (
                    "This domain resembles a domain previously "
                    "submitted to community intelligence."
                )
            })

    # Exact matches always appear before similar matches.
    exact_matches.sort(
        key=lambda item: item["last_reported_at"] or "",
        reverse=True
    )

    similar_matches.sort(
        key=lambda item: item["similarity"],
        reverse=True
    )

    related_domains = (
        exact_matches + similar_matches
    )[:5]

    # --------------------------------------------------------
    # 3. Generate Threat DNA signals and profile.
    # --------------------------------------------------------

    signals = []

    if brand_matches:
        signals.append("Potential brand-name impersonation")

    if exact_matches:
        signals.append("Exact match to community-reported domain")

    if similar_matches:
        signals.append("Similarity to community-reported domains")

    if brand_matches and exact_matches:
        profile = "Brand impersonation and exact community match"

    elif exact_matches:
        profile = "Exact community-reported domain match"

    elif brand_matches and similar_matches:
        profile = "Multiple correlated indicators"

    elif brand_matches:
        profile = "Potential brand impersonation"

    elif similar_matches:
        profile = "Similar community-reported domains"

    else:
        profile = "No strong domain links found"

    return {
        "profile": profile,
        "brand_lookalikes": brand_matches,
        "related_community_domains": related_domains,
        "signals": signals,
        "note": (
            "Similarity indicates a possible relationship, not proof "
            "that domains share an owner or attacker. Community reports "
            "are unverified unless separately reviewed."
        )
    }


# ============================================================
# THREAT DOMAIN VALIDATION
# ============================================================

def extract_threat_domain(value: str) -> str:

    value = value.strip()

    if not value:
        raise ValueError("Enter a domain name")

    if re.match(r"^https?://", value, re.I):
        parsed = urlparse(value)
    else:
        parsed = urlparse("//" + value)

    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid domain name")

    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    try:
        host = (
            parsed.hostname.encode("idna")
            .decode("ascii")
            .lower()
            .rstrip(".")
        )
    except UnicodeError:
        raise ValueError("Invalid internationalized domain name")

    if len(host) > 253:
        raise ValueError("Domain name is too long")

    label_pattern = (
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
    )

    if not re.fullmatch(label_pattern, host):
        raise ValueError("Enter a valid public domain name")

    try:
        ipaddress.ip_address(host)
        raise ValueError("Enter a domain name, not an IP address")
    except ValueError as exc:
        if str(exc) == "Enter a domain name, not an IP address":
            raise

    return host


# ============================================================
# MAIN SCAN ENGINE
# ============================================================

def run_scan(raw_url: str) -> dict[str, Any]:

    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)

    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    resolve_public_host(host, port)

    url_score, url_findings = url_analysis(normalized, host)

    response, final_url, redirects = safe_fetch(normalized)

    header_score, header_findings, headers = header_analysis(response)

    cert = (
        certificate_check(host, port=443)
        if parsed.scheme == "https"
        else {
            "checked": False,
            "valid": False,
            "error": "The submitted URL does not use HTTPS."
        }
    )

    cert_score = 0
    cert_findings: list[dict[str, str]] = []

    if (
        parsed.scheme == "https"
        and cert.get("checked")
        and not cert.get("valid")
    ):
        cert_score += 25

        cert_findings.append({
            "severity": "high",
            "title": "TLS certificate validation failed",
            "detail": (
                cert.get("error")
                or "The certificate trust or hostname validation failed."
            )
        })

    elif parsed.scheme == "https" and not cert.get("checked"):
        cert_findings.append({
            "severity": "info",
            "title": "TLS inspection unavailable",
            "detail": (
                cert.get("error")
                or "The scanner could not complete a certificate inspection. "
                "This is not counted as proof of an invalid certificate."
            )
        })

    if (
        cert.get("days_remaining") is not None
        and cert["days_remaining"] < 21
    ):
        cert_score += 8

        cert_findings.append({
            "severity": "medium",
            "title": "Certificate expires soon",
            "detail": (
                f"The certificate has {cert['days_remaining']} days remaining."
            )
        })

    if redirects:
        url_findings.append({
            "severity": "info",
            "title": "Redirect chain observed",
            "detail": (
                f"The scanner observed {len(redirects)} redirect(s). "
                f"Final destination: {final_url}"
            )
        })

    reports = community_matches(host)
    threat_dna = threat_dna_analysis(host)

    # Repeat submissions do not increase the risk score.
    # Only unique matching report records are counted.
    community_score = min(30, len(reports) * 15)

    if reports:
        url_findings.append({
            "severity": "high",
            "title": "Community reports found",
            "detail": (
                f"{len(reports)} community report(s) exist for this hostname. "
                "Reports are unverified unless separately reviewed."
            )
        })

    score = min(
        100,
        url_score + header_score + cert_score + community_score
    )

    verdict = (
        "High Risk" if score >= 60
        else "Elevated Risk" if score >= 35
        else "Low Risk" if score >= 15
        else "No major indicators found"
    )

    all_findings = (
        url_findings + header_findings + cert_findings
    )

    if not all_findings:
        all_findings.append({
            "severity": "info",
            "title": "No major indicators found by this prototype",
            "detail": (
                "This is not a guarantee that the website is safe. "
                "Reputation feeds and deeper behavioural analysis "
                "are not yet connected."
            )
        })

    result = {
        "url": normalized,
        "host": host,
        "final_url": final_url,
        "score": score,
        "verdict": verdict,
        "risk_level": (
            "high" if score >= 60
            else "medium" if score >= 35
            else "low"
        ),
        "components": {
            "url_heuristics": url_score,
            "security_headers": header_score,
            "certificate": cert_score,
            "community_reports": community_score
        },
        "findings": all_findings,
        "certificate": cert,
        "security_headers": headers,
        "http_status": response.status_code if response else None,
        "redirects": redirects,
        "community_reports": reports,
        "threat_dna": threat_dna,
        "limitations": [
            "Heuristic indicators are not proof of malicious activity.",
            "No external commercial reputation feed or trained ML model is connected in this prototype.",
            "A valid HTTPS certificate does not establish that a website operator is trustworthy."
        ],
        "scanned_at": datetime.now(timezone.utc).isoformat()
    }

    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans
            (url, host, score, verdict, findings_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                normalized,
                host,
                score,
                verdict,
                json.dumps(result),
                result["scanned_at"]
            )
        )

        result["scan_id"] = cur.lastrowid

    return result


# ============================================================
# API ROUTES
# ============================================================

@app.get("/")
def home() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "SENTINEL X",
        "version": "0.1.0"
    }


@app.post("/api/scan")
def scan(payload: ScanRequest) -> dict[str, Any]:

    try:
        return run_scan(payload.url)

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Scan could not be completed: {str(exc)[:180]}"
        )


# Standalone Threat DNA endpoint.
# This endpoint does NOT perform DNS resolution or HTTP requests.
@app.post("/api/threat-dna")
def analyze_threat_dna(
    payload: ThreatDNARequest
) -> dict[str, Any]:

    try:
        host = extract_threat_domain(payload.domain)

        return {
            "domain": host,
            "analysis_type": "offline_domain_intelligence",
            "dns_resolution_required": False,
            "threat_dna": threat_dna_analysis(host)
        }

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Threat DNA analysis failed: {str(exc)[:180]}"
        )


@app.post("/api/reports")
def submit_report(payload: ReportRequest) -> dict[str, Any]:

    raw = payload.url.strip()

    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw

    parsed = urlparse(raw)

    if (
        not parsed.hostname
        or parsed.scheme not in ("http", "https")
        or parsed.username
        or parsed.password
    ):
        raise HTTPException(
            status_code=400,
            detail="Enter a valid HTTP or HTTPS URL"
        )

    host = parsed.hostname.lower().rstrip(".")
    category = payload.category.strip()

    if not category:
        raise HTTPException(
            status_code=400,
            detail="Select a valid report category"
        )

    now = datetime.now(timezone.utc).isoformat()

    try:
        with db() as conn:

            # Increment the count if this host/category already exists.
            updated = conn.execute(
                """
                UPDATE reports
                SET submission_count = submission_count + 1,
                    last_reported_at = ?
                WHERE normalized_host = ? AND category = ?
                """,
                (now, host, category)
            )

            if updated.rowcount > 0:

                existing = conn.execute(
                    """
                    SELECT id, submission_count, last_reported_at
                    FROM reports
                    WHERE normalized_host = ? AND category = ?
                    """,
                    (host, category)
                ).fetchone()

                return {
                    "id": existing["id"],
                    "status": "duplicate",
                    "duplicate": True,
                    "submission_count": existing["submission_count"],
                    "last_reported_at": existing["last_reported_at"],
                    "message": (
                        "This website and category already exist in "
                        "community intelligence. The repeat submission "
                        "has been recorded."
                    )
                }

            cur = conn.execute(
                """
                INSERT INTO reports
                (
                    url,
                    normalized_host,
                    category,
                    details,
                    created_at,
                    submission_count,
                    last_reported_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalize_url(raw),
                    host,
                    category,
                    payload.details.strip(),
                    now,
                    1,
                    now
                )
            )

            report_id = cur.lastrowid

    except sqlite3.IntegrityError:

        # Handle simultaneous submissions safely.
        with db() as conn:

            conn.execute(
                """
                UPDATE reports
                SET submission_count = submission_count + 1,
                    last_reported_at = ?
                WHERE normalized_host = ? AND category = ?
                """,
                (now, host, category)
            )

            existing = conn.execute(
                """
                SELECT id, submission_count, last_reported_at
                FROM reports
                WHERE normalized_host = ? AND category = ?
                """,
                (host, category)
            ).fetchone()

        if existing:
            return {
                "id": existing["id"],
                "status": "duplicate",
                "duplicate": True,
                "submission_count": existing["submission_count"],
                "last_reported_at": existing["last_reported_at"],
                "message": "The repeat submission has been recorded."
            }

        raise HTTPException(
            status_code=500,
            detail="Could not save the community report"
        )

    return {
        "id": report_id,
        "status": "community-reported",
        "duplicate": False,
        "submission_count": 1,
        "last_reported_at": now,
        "message": (
            "Report added to the community intelligence queue. "
            "It is not yet verified."
        )
    }


@app.get("/api/reports")
def list_reports() -> dict[str, Any]:

    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, url, normalized_host, category, details,
                   status, created_at, submission_count, last_reported_at
            FROM reports
            ORDER BY id DESC LIMIT 50
            """
        ).fetchall()

    return {
        "reports": [dict(row) for row in rows]
    }


@app.get("/api/scans/recent")
def recent_scans() -> dict[str, Any]:

    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, url, host, score, verdict, created_at
            FROM scans
            ORDER BY id DESC LIMIT 10
            """
        ).fetchall()

    return {
        "scans": [dict(row) for row in rows]
    }
