"""
LinkedIn + JobStreet Job Alert -> Telegram

Checks LinkedIn and JobStreet for new postings matching your keywords/location,
and pushes new ones to Telegram. Runs on GitHub Actions on a schedule.

Jobs are sorted into "tracks" (Security, Network, Data Centre). A job is sent if
its title passes at least one track's gate: it must contain one of that track's
required terms and none of that track's excluded terms. All term matching is
whole-word, so "hr" no longer matches "threat" and "soc" no longer matches
"associate".
"""

import os
import sys
import json
import time
import html
import re
from datetime import datetime, timedelta, timezone

import requests
from bs4 import BeautifulSoup
from curl_cffi import requests as creq  # browser-TLS impersonation (JobStreet/Akamai)

# ----------------------------- CONFIG -----------------------------

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# JobStreet (my.jobstreet.com) is Akamai IP-blocked from datacenter IPs like
# GitHub Actions runners — it only works from a residential IP (e.g. your PC).
# Default ON for local runs; the GitHub workflow sets JOBSTREET_ENABLED=false.
JOBSTREET_ENABLED = os.environ.get("JOBSTREET_ENABLED", "true").strip().lower() not in (
    "false", "0", "no", "off",
)

SEEN_FILE = "seen_jobs.json"
# Forget a job ID this many days after it was first seen. LinkedIn/JobStreet
# listings rarely stay up longer, and the search window is only hours wide.
SEEN_RETENTION_DAYS = 60

# ---- Search keywords (what gets queried; the track gates below decide what's sent)

SECURITY_KEYWORDS = [
    # Core SOC titles (primary focus)
    "SOC Analyst",
    "SOC Engineer",
    "Security Operations Center",
    "Security Operations",
    "Cyber Security Analyst",
    # Broader cybersecurity
    "Cybersecurity",
    "Cyber Security",
    "Security Analyst",
    "Security Engineer",
    "Information Security",
    "IT Security",
    "Network Security",
    "Cyber Defence",
    # Detection / response / intel
    "Incident Response",
    "Threat Analyst",
    "Threat Intelligence",
    "SIEM",
    "Vulnerability Analyst",
    # Offensive / GRC
    "Penetration Tester",
    "VAPT",
    "Security Consultant",
    "GRC",
    "Associate Security",
]

NETWORK_KEYWORDS = [
    "Network Engineer",
    "Junior Network Engineer",
    "Network Administrator",
    "Network Support Engineer",
    "NOC Engineer",
]

DATACENTRE_KEYWORDS = [
    "Data Centre Technician",
    "Data Center Technician",
    "Data Centre Engineer",
    "Data Center Operations",
    "Critical Facilities Technician",
]

# Fresh-grad entry points — broad, so they only pull candidates; a job still has
# to pass one of the track gates to be sent.
FRESH_GRAD_KEYWORDS = [
    "Fresh Graduate",
    "Graduate Trainee",
    "Graduate Programme",
    "Management Trainee",
]

KEYWORDS = SECURITY_KEYWORDS + NETWORK_KEYWORDS + DATACENTRE_KEYWORDS + FRESH_GRAD_KEYWORDS

# LinkedIn — single centre-point + radius (25 miles ~ 40km covers full Klang Valley)
LINKEDIN_LOCATION = "Kuala Lumpur, Malaysia"
DISTANCE_MILES = 25

# JobStreet — per-location configs with keyword scoping
# KL/Selangor : all keywords
# Johor Bahru : security + DC/network keywords (data centre boom)
# Penang      : target companies only (manufacturing IT, selective)
JOBSTREET_LOCATION_CONFIGS = [
    {
        "location": "Kuala Lumpur",
        "keywords": "all",
        "companies_only": False,
    },
    {
        "location": "Selangor",
        "keywords": "all",
        "companies_only": False,
    },
    {
        "location": "Johor Bahru",
        "keywords": [
            "SOC Analyst",
            "SOC Engineer",
            "Security Operations",
            "Security Engineer",
            "Cybersecurity",
            "Information Security",
            "Incident Response",
            "Network Engineer",
            "NOC Engineer",
            "Data Centre Technician",
            "Data Center Technician",
            "Data Centre Engineer",
            "Data Center Operations",
            "Critical Facilities Technician",
        ],
        "companies_only": False,
    },
    {
        "location": "Penang",
        "keywords": [
            "SOC Analyst",
            "Security Analyst",
            "IT Security",
            "Information Security",
            "Network Engineer",
        ],
        "companies_only": True,  # only post if it's a target company
    },
]

# How far back each run looks — kept wider than run interval to avoid edge misses
TIME_WINDOW_SECONDS = 3 * 60 * 60  # 3 hours (LinkedIn, supports second granularity)

# JobStreet only supports day-granularity date filters: 1, 3, 7, 14, 31.
# 1 = past 24h; dedup via seen_jobs.json handles the overlap between runs.
JOBSTREET_DATERANGE_DAYS = 1

RESULTS_PER_KEYWORD = 25

# ---- Title filters (all matched as whole words/phrases, case-insensitive)

# Applies to every track
SENIORITY_EXCLUDE = [
    "senior", "sr", "lead", "principal", "head of", "director",
    "manager", "supervisor", "vp", "vice president",
    "5+ years", "7+ years", "10+ years",
    "internship", "intern", "interns",
]

# Wrong-domain titles. Used by the Security and Network tracks.
DOMAIN_EXCLUDE = [
    "software", "frontend", "backend", "fullstack", "full stack",
    "mobile", "android", "ios", "flutter", "react", "devops",
    "data scientist", "data engineer", "machine learning engineer",
    "mechanical", "electrical", "civil", "structural", "quantity surveyor",
    "food", "kitchen", "chef", "barista", "crew", "cashier",
    "marketing", "sales", "business development", "bd",
    "hr", "human resource", "human resources", "recruitment", "talent acquisition",
    "credit", "loan", "mortgage", "insurance", "actuarial",
    "driver", "despatch", "cleaner", "housekeeping",
    "japanese", "mandarin", "korean", "arabic",
    "qc", "qa", "procurement", "data analyst",
    "backup", "quality", "maintenance", "cleanroom",
    "transaction", "medical",
    "travel", "customer", "test process", "inventory",
    "developer", "content", "logistics", "equipment", "qs",
    "chemical", "solar", "pest", "clerk", "assembler", "bartender",
    "hospitality", "controls",
]

# Data-centre technician roles are often facilities-side (power, cooling), so
# don't block electrical/mechanical/maintenance/equipment/controls for that track.
DC_ALLOWED_DOMAIN_TERMS = {"electrical", "mechanical", "maintenance", "equipment", "controls"}
DATACENTRE_DOMAIN_EXCLUDE = [t for t in DOMAIN_EXCLUDE if t not in DC_ALLOWED_DOMAIN_TERMS]

# Physical-security titles ("Security Officer") are dropped unless the title
# also says it's an IT/cyber role ("IT Security Officer").
PHYSICAL_SECURITY_TERMS = ["security guard", "security officer", "physical security", "guard"]
CYBER_CONTEXT_TERMS = ["it", "ict", "information", "cyber", "cybersecurity", "network", "soc"]

TRACKS = [
    {
        "name": "Security",
        "icon": "\U0001F6E1️",  # 🛡️
        "require": [
            "soc", "security", "cyber", "cybersecurity",
            "threat", "incident", "vulnerability", "vapt",
            "penetration", "pentest", "pentester", "siem", "grc",
            "infosec", "malware", "forensic", "forensics",
            "red team", "blue team", "detection",
        ],
        "exclude": DOMAIN_EXCLUDE,
    },
    {
        "name": "Network",
        "icon": "\U0001F310",  # 🌐
        "require": [
            "network engineer", "network engineers", "network administrator",
            "network admin", "network support", "network operations",
            "network technician", "network specialist", "network analyst",
            "network infrastructure", "networking", "noc",
        ],
        "exclude": DOMAIN_EXCLUDE,
    },
    {
        "name": "Data Centre",
        "icon": "\U0001F5C4️",  # 🗄️
        "require": [
            "data centre", "data center", "datacentre", "datacenter",
            "data centres", "data centers",
            "dc technician", "dc engineer", "dc operations",
            "critical facilities", "critical facility", "critical environment",
        ],
        "exclude": DATACENTRE_DOMAIN_EXCLUDE,
    },
]

# Jobs from these companies get a ⭐ PRIORITY flag in the Telegram message.
# Matched as whole words against the company name, so keep short names specific
# (e.g. "time dotcom", not "time").
TARGET_COMPANIES = [
    # Central bank / regulators
    "bank negara malaysia", "bnm",
    # Commercial banks
    "maybank", "malayan banking",
    "cimb",
    "public bank",
    "rhb",
    "ambank",
    "hong leong bank", "hong leong",
    "alliance bank",
    "hsbc",
    "standard chartered",
    "affin bank", "affin",
    "mbsb",
    "kenanga",
    # Islamic banks
    "bank islam",
    # Digital banks
    "tng digital", "touch n go", "touch 'n go",
    "gxbank", "gx bank",
    "ryt bank",
    "bigpay",
    "boost bank", "boost holdings", "boost credit",
    # Payment infra
    "paynet",
    "setel",
    # GLCs / investment
    "khazanah",
    "pnb", "permodalan nasional berhad",
    # Telcos
    "maxis",
    "celcomdigi", "celcom", "digi telecommunications",
    "telekom malaysia", "tm one", "tm global", "tm technology services", "unifi",
    "time dotcom", "timedotcom",
    "u mobile",
    # Network / security vendors
    "cisco",
    "huawei",
    "fortinet",
    "palo alto networks",
    "juniper networks",
    "f5", "f5 networks",
    # Cloud / big tech
    "microsoft",
    "google",
    "amazon", "aws", "amazon web services",
    "dell technologies", "dell",
    "hpe", "hewlett packard enterprise",
    "amd", "advanced micro devices",
    # System integrators / MSPs
    "accenture",
    "bridgenet",
    "ntt", "ntt data", "ntt malaysia",
    "dimension data",
    "dxc technology", "dxc",
    "ibm",
    "avanade",
    # Government cybersecurity agencies
    "cybersecurity malaysia",
    "nacsa",
    "mdec",
    "mcmc",
    # Data centres
    "aims data centre", "aims data center", "aims group",
    "vads",
    "bridge data centres", "bridge data centers",
    "yondr",
    "equinix",
    "stack infrastructure",
    "princeton digital group",
    "keppel data centres",
    "digital realty",
    "airtrunk",
    "ytl data centre", "ytl",
    # Fintech
    "grabpay", "grab",
    "slb", "schlumberger",
    # Automotive (low priority)
    "mercedes-benz malaysia",
    # Sandisk / Western Digital (Penang)
    "sandisk", "western digital",
]

# Salary filter: skip only if salary is SHOWN and below threshold
# No salary shown -> always post, you decide
MIN_SALARY_MYR = 3000

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ------------------------------------------------------------------ Matching


def _term_pattern(term):
    """Whole-word/phrase pattern: the term can't be glued to other letters or digits."""
    return r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"


def build_matcher(terms):
    """Compile a list of terms into one case-insensitive whole-word regex."""
    if not terms:
        return re.compile(r"(?!x)x")  # matches nothing
    # Longest first so multi-word phrases win over their single-word prefixes.
    ordered = sorted({_normalise(t) for t in terms if _normalise(t)}, key=len, reverse=True)
    return re.compile("|".join(_term_pattern(t) for t in ordered), re.IGNORECASE)


def _normalise(text):
    # Treat separators like "-", "/", "|" and "&" as spaces so "Network/Security"
    # and "Data-Centre" still match their phrases.
    text = (text or "").lower()
    text = re.sub(r"[\-_/|&,()\[\]]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


SENIORITY_RE = build_matcher(SENIORITY_EXCLUDE)
PHYSICAL_RE = build_matcher(PHYSICAL_SECURITY_TERMS)
CYBER_CONTEXT_RE = build_matcher(CYBER_CONTEXT_TERMS)
TARGET_RE = build_matcher(TARGET_COMPANIES)
for _t in TRACKS:
    _t["require_re"] = build_matcher(_t["require"])
    _t["exclude_re"] = build_matcher(_t["exclude"])


def match_tracks(title):
    """Return the names of every track whose gate this title passes."""
    t = _normalise(title)
    if SENIORITY_RE.search(t):
        return []
    if PHYSICAL_RE.search(t) and not CYBER_CONTEXT_RE.search(t):
        return []
    return [
        trk["name"] for trk in TRACKS
        if trk["require_re"].search(t) and not trk["exclude_re"].search(t)
    ]


def is_target_company(company):
    return bool(TARGET_RE.search(_normalise(company)))


# ------------------------------------------------------------------ Seen store


def _now():
    return datetime.now(timezone.utc)


def load_seen():
    """
    Returns {job_id: first_seen_iso}. Accepts the old {"seen_ids": [...]} format
    too; those IDs are stamped with the current time so they age out normally.
    """
    if not os.path.exists(SEEN_FILE):
        return {}
    try:
        with open(SEEN_FILE, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}

    if isinstance(data.get("seen"), dict):
        return {str(k): str(v) for k, v in data["seen"].items()}

    stamp = _now().isoformat(timespec="seconds")
    return {str(i): stamp for i in data.get("seen_ids", [])}


def save_seen(seen):
    cutoff = _now() - timedelta(days=SEEN_RETENTION_DAYS)
    kept = {}
    for job_id, stamp in seen.items():
        try:
            when = datetime.fromisoformat(stamp)
        except ValueError:
            when = _now()
        if when >= cutoff:
            kept[job_id] = when.isoformat(timespec="seconds")
    # Stable, sorted output keeps the bot's commits small and readable.
    ordered = dict(sorted(kept.items(), key=lambda kv: (kv[1], kv[0])))
    with open(SEEN_FILE, "w") as f:
        json.dump({"seen": ordered}, f, indent=2)
        f.write("\n")


# ------------------------------------------------------------------ Salary


def parse_salary_myr(salary_text):
    """
    Extract lower-bound monthly salary from freeform text.
    Returns int (MYR/month) or None if unparseable.
    Handles:
        "MYR 3,000 - MYR 5,000 per month"  -> 3000
        "RM3500/month"                       -> 3500
        "MYR 42,000 per year"               -> 3500
        "RM 3.5k - 4.5k"                     -> 3500
    """
    if not salary_text:
        return None
    text = salary_text.replace(",", "").upper()
    m = re.search(r"(\d+(?:\.\d+)?)\s*(K)?", text)
    if not m:
        return None
    lower = float(m.group(1))
    if m.group(2):
        lower *= 1000
    if "YEAR" in text or "ANNUAL" in text or lower > 50000:
        lower = lower / 12
    return int(lower)


# ------------------------------------------------------------------ LinkedIn


def fetch_jobs_linkedin(keyword):
    url = "https://www.linkedin.com/jobs-guest/jobs/api/seeMoreJobPostings/search"
    params = {
        "keywords": keyword,
        "location": LINKEDIN_LOCATION,
        "distance": DISTANCE_MILES,
        "f_TPR": f"r{TIME_WINDOW_SECONDS}",
        "start": 0,
    }
    resp = None
    for attempt in range(2):
        try:
            resp = requests.get(url, params=params, headers=HEADERS, timeout=15)
            if resp.status_code == 429 and attempt == 0:
                print(f"[warn] LinkedIn rate-limited on '{keyword}', backing off 30s")
                time.sleep(30)
                continue
            resp.raise_for_status()
            break
        except requests.RequestException as e:
            print(f"[warn] LinkedIn request failed for '{keyword}': {e}")
            return []
    if resp is None or not resp.ok:
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    jobs = []

    for card in soup.find_all("li")[:RESULTS_PER_KEYWORD]:
        try:
            base = card.find("div", class_="base-card")
            job_id = (base.get("data-entity-urn", "") if base else "").split(":")[-1]

            title_tag = card.find("h3", class_="base-search-card__title")
            company_tag = card.find("h4", class_="base-search-card__subtitle")
            location_tag = card.find("span", class_="job-search-card__location")
            link_tag = card.find("a", class_="base-card__full-link")
            posted_tag = card.find("time")

            if not job_id or not link_tag or not title_tag:
                continue

            jobs.append({
                "id": f"li_{job_id}",
                "title": title_tag.get_text(strip=True),
                "company": company_tag.get_text(strip=True) if company_tag else "Unknown",
                "location": location_tag.get_text(strip=True) if location_tag else "Unknown",
                "salary_text": "",
                "link": link_tag["href"].split("?")[0],
                "posted": posted_tag.get_text(strip=True) if posted_tag else "recently",
                "matched_keyword": keyword,
                "source": "LinkedIn",
                "companies_only": False,
            })
        except (AttributeError, KeyError):
            continue

    return jobs


# ------------------------------------------------------------------ JobStreet


def _parse_jobstreet_redux(html_text):
    """Pull the jobs list out of the window.SEEK_REDUX_DATA blob embedded in the page."""
    m = re.search(r"window\.SEEK_REDUX_DATA\s*=\s*(\{.*?\});", html_text, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return []
    return data.get("results", {}).get("results", {}).get("jobs", []) or []


def fetch_jobs_jobstreet(keyword):
    """
    Scrapes JobStreet (my.jobstreet.com, SEEK platform) per JOBSTREET_LOCATION_CONFIGS.
    Uses curl_cffi to impersonate a real browser's TLS handshake — the plain
    `requests` client gets 403'd by Akamai bot detection.

    Each config defines which keywords apply and whether to restrict to target
    companies only (e.g. Penang).
    """
    all_jobs = []
    seen_in_call = set()

    for config in JOBSTREET_LOCATION_CONFIGS:
        loc = config["location"]
        allowed_keywords = config.get("keywords", "all")
        companies_only = config.get("companies_only", False)

        # Skip this location if the current keyword isn't in its allowed list
        if allowed_keywords != "all" and keyword not in allowed_keywords:
            continue

        params = {
            "keywords": keyword,
            "where": loc,
            "daterange": JOBSTREET_DATERANGE_DAYS,
        }
        try:
            resp = creq.get(
                "https://my.jobstreet.com/jobs",
                params=params,
                impersonate="chrome",
                timeout=20,
            )
            resp.raise_for_status()
        except Exception as e:  # curl_cffi raises its own error types
            print(f"[warn] JobStreet request failed for '{keyword}' in {loc}: {e}")
            time.sleep(2)
            continue

        for j in _parse_jobstreet_redux(resp.text):
            try:
                raw_id = j.get("id") or ""
                job_id = f"js_{raw_id}"
                if not raw_id or job_id in seen_in_call:
                    continue

                advertiser = j.get("advertiser") or {}
                company = j.get("companyName") or advertiser.get("description") or "Unknown"

                locations = j.get("locations") or []
                loc_label = locations[0].get("label") if locations else loc

                # Fold work arrangement (On-site / Hybrid / Remote) into the location
                # string so the shared is_relevant() remote filter still applies.
                arrangements = ((j.get("workArrangements") or {}).get("data")) or []
                arr_texts = [
                    (a.get("label") or {}).get("text", "") for a in arrangements
                ]
                arr = ", ".join(t for t in arr_texts if t)
                location_str = f"{loc_label} ({arr})" if arr else loc_label

                seen_in_call.add(job_id)
                all_jobs.append({
                    "id": job_id,
                    "title": j.get("title") or "",
                    "company": company,
                    "location": location_str,
                    "salary_text": j.get("salaryLabel") or "",
                    "link": f"https://my.jobstreet.com/job/{raw_id}",
                    "posted": j.get("listingDateDisplay") or j.get("listingDate") or "recently",
                    "matched_keyword": keyword,
                    "source": "JobStreet",
                    "companies_only": companies_only,
                })
            except (KeyError, TypeError, AttributeError):
                continue

        time.sleep(2)

    return all_jobs


# ------------------------------------------------------------------ Filters


def is_relevant(job):
    """True if the job passes a track gate plus the location/company/salary rules.
    Stores the matched tracks on job["tracks"] for the Telegram message."""
    tracks = match_tracks(job.get("title", ""))
    if not tracks:
        return False

    loc = job.get("location", "").lower()

    # Physical roles only
    if "remote" in loc:
        return False

    # Malaysia only
    if any(c in loc for c in ["singapore", "indonesia", "thailand", "philippines"]):
        return False

    # Penang: only post if it's a target company
    if job.get("companies_only", False) and not is_target_company(job.get("company", "")):
        return False

    # Salary filter: only skip if salary is explicitly shown AND below threshold
    salary_text = job.get("salary_text", "")
    if salary_text:
        lower_bound = parse_salary_myr(salary_text)
        if lower_bound is not None and lower_bound < MIN_SALARY_MYR:
            return False

    job["tracks"] = tracks
    return True


# ------------------------------------------------------------------ Telegram

TRACK_ICONS = {t["name"]: t["icon"] for t in TRACKS}


def format_message(job):
    source = job.get("source", "LinkedIn")
    icon = "\U0001F535" if source == "LinkedIn" else "\U0001F7E1"  # 🔵 🟡

    # Priority flag if company is in your target list
    priority_tag = (
        "⭐ <b>PRIORITY COMPANY</b>\n" if is_target_company(job.get("company", "")) else ""
    )

    tracks = job.get("tracks") or []
    track_line = ""
    if tracks:
        track_line = " ".join(f"{TRACK_ICONS.get(t, '')} {html.escape(t)}" for t in tracks) + "\n"

    salary_line = ""
    if job.get("salary_text"):
        salary_line = f"\U0001F4B0 {html.escape(str(job['salary_text']))}\n"

    return (
        f"{priority_tag}"
        f"{icon} <b>[{source}]</b>  \U0001F195 <b>{html.escape(job['title'])}</b>\n"
        f"{track_line}"
        f"\U0001F3E2 {html.escape(job['company'])}\n"
        f"\U0001F4CD {html.escape(job['location'])}\n"
        f"{salary_line}"
        f"\U0001F552 Posted: {html.escape(job['posted'])}\n"
        f"\U0001F50E Keyword: {html.escape(job['matched_keyword'])}\n"
        f'<a href="{html.escape(job["link"], quote=True)}">Apply / View</a>'
    )


def send_telegram(job):
    """Send one job. Returns True only if Telegram accepted it."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": format_message(job),
        "parse_mode": "HTML",
        "disable_web_page_preview": False,
    }
    for attempt in range(2):
        try:
            r = requests.post(url, data=payload, timeout=15)
        except requests.RequestException as e:
            print(f"[warn] Telegram send failed: {e}")
            return False
        if r.status_code == 429 and attempt == 0:
            # Telegram tells us how long to wait when we send too fast.
            try:
                wait = int(r.json().get("parameters", {}).get("retry_after", 5))
            except ValueError:
                wait = 5
            time.sleep(min(wait, 60))
            continue
        if not r.ok:
            print(f"[warn] Telegram send failed: HTTP {r.status_code} {r.text[:200]}")
            return False
        return True
    return False


def send_test_message():
    ok1 = send_telegram({
        "title": "Setup check ✅",
        "company": "Maybank",
        "location": "Kuala Lumpur, Malaysia",
        "salary_text": "MYR 4,000 - MYR 6,000",
        "posted": "just now",
        "matched_keyword": "this is a test — not a real job",
        "link": "https://www.linkedin.com/jobs/",
        "source": "LinkedIn",
        "tracks": ["Security"],
    })
    ok2 = send_telegram({
        "title": "Setup check ✅",
        "company": "Unknown Co",
        "location": "Selangor, Malaysia",
        "salary_text": "",
        "posted": "just now",
        "matched_keyword": "this is a test — not a real job",
        "link": "https://www.jobstreet.com.my/jobs",
        "source": "JobStreet",
        "tracks": ["Network", "Data Centre"],
    })
    if ok1 and ok2:
        print("Two test messages sent (LinkedIn priority + JobStreet non-priority). Check Telegram.")
    else:
        print("[error] At least one test message failed — see warnings above.")
        sys.exit(1)


# ------------------------------------------------------------------ Main


def main():
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[error] TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID env vars missing.")
        sys.exit(1)

    if "--test" in sys.argv:
        send_test_message()
        return

    sources = "LinkedIn + JobStreet" if JOBSTREET_ENABLED else "LinkedIn only (JobStreet disabled)"
    print(f"Sources: {sources}")
    print(f"Tracks: {', '.join(t['name'] for t in TRACKS)} | {len(KEYWORDS)} keywords")

    seen = load_seen()
    queued = set()  # IDs picked up this run (avoid duplicates across keywords)
    new_jobs = []

    def consider(job):
        if job["id"] in seen or job["id"] in queued:
            return
        if is_relevant(job):
            new_jobs.append(job)
            queued.add(job["id"])

    for kw in KEYWORDS:
        for job in fetch_jobs_linkedin(kw):
            consider(job)
        time.sleep(2)

        # JobStreet (my.jobstreet.com via curl_cffi browser impersonation).
        # Skipped when JOBSTREET_ENABLED=false (e.g. on GitHub Actions, where the
        # runner IP is blocked by Akamai — see note at top of file).
        if JOBSTREET_ENABLED:
            for job in fetch_jobs_jobstreet(kw):
                consider(job)
            time.sleep(2)

    print(f"Found {len(new_jobs)} new matching job(s).")
    sent = failed = 0
    for job in new_jobs:
        # Only remember a job once Telegram has actually accepted it, so a
        # failed send gets retried on the next run instead of being lost.
        if send_telegram(job):
            seen[job["id"]] = _now().isoformat(timespec="seconds")
            sent += 1
        else:
            failed += 1
        time.sleep(1)
    print(f"Sent {sent}, failed {failed} (failed ones will be retried next run).")

    save_seen(seen)


if __name__ == "__main__":
    main()
