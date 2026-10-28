# Job Alert -> Telegram (LinkedIn + JobStreet)

Checks LinkedIn (and JobStreet, when run locally) for new entry-level postings around
Kuala Lumpur / Selangor and pings you on Telegram the moment it finds something new.
Runs on GitHub Actions, so it works even when your PC is off.

It watches three tracks:

| Track | Example titles it sends |
|---|---|
| 🛡️ **Security** | SOC Analyst, Cyber Security Analyst, Threat Intelligence Analyst, IT Security Officer, VAPT |
| 🌐 **Network** | Network Engineer, Junior Network Engineer, Network Administrator, NOC Engineer |
| 🗄️ **Data Centre** | Data Centre Technician, Data Center Operations Engineer, Critical Facilities Technician |

Each Telegram alert shows which track(s) the job matched, plus a ⭐ PRIORITY tag when
the company is on your target list.

## How it works

- A GitHub Actions workflow runs `linkedin_job_alert.py` every 2 hours, 8am–10pm
  Malaysia time (8 runs/day).
- For every search keyword, the script pulls LinkedIn's public job-search results
  (no login needed) from the last 3 hours.
- Each title is checked against the track gates (see *Tuning it*). Remote roles,
  non-Malaysia roles, and roles with a shown salary under RM 3,000 are dropped.
- New matches are pushed to Telegram. A job is only remembered in `seen_jobs.json`
  **after Telegram confirms delivery**, so a failed send is retried on the next run.
- Seen IDs are stored with the date they were first sent and forgotten after
  60 days.

**Heads up:** this uses LinkedIn's public search page, not an official API (LinkedIn
doesn't offer one for this use case). It's not bypassing any login or auth, but
LinkedIn can change their page layout or rate-limit requests without warning, so the
script may occasionally need a small fix. As a free backup, also turn on LinkedIn's
own job alerts: save a search on linkedin.com and toggle "Email me about new jobs".

### JobStreet

JobStreet blocks GitHub's datacenter IPs, so the workflow runs with
`JOBSTREET_ENABLED=false`. Run the script on your own PC to include JobStreet:

```bash
pip install -r requirements.txt
TELEGRAM_BOT_TOKEN=xxx TELEGRAM_CHAT_ID=123456789 python3 linkedin_job_alert.py
```

## One-time setup (~10 minutes)

1. **Create a GitHub repo** (private is fine) and upload these files, keeping the
   folder structure (`.github/workflows/job_alert.yml` is what makes it scheduled).
2. **Add your secrets**: `Settings → Secrets and variables → Actions → New repository
   secret`:
   - `TELEGRAM_BOT_TOKEN`: your bot token
   - `TELEGRAM_CHAT_ID`: your chat ID

   Don't put these values in the code; secrets keep them out of your commit history.
3. **Allow the workflow to commit**: `Settings → Actions → General → Workflow
   permissions` → **Read and write permissions** → Save. This lets each run update
   `seen_jobs.json`.
4. **Test it**: **Actions** tab → "LinkedIn Job Alert" → **Run workflow**. Check the
   run log and Telegram. If nothing matched in the last 3 hours you won't get a
   message; that's expected.

   To check Telegram delivery on its own (skips LinkedIn entirely):
   ```bash
   TELEGRAM_BOT_TOKEN=xxx TELEGRAM_CHAT_ID=123456789 python3 linkedin_job_alert.py --test
   ```

## Tuning it

All the knobs are constants at the top of `linkedin_job_alert.py`.

| Variable | What it controls |
|---|---|
| `SECURITY_KEYWORDS`, `NETWORK_KEYWORDS`, `DATACENTRE_KEYWORDS`, `FRESH_GRAD_KEYWORDS` | What gets searched. Searching only fetches candidates; the track gates decide what's sent. |
| `TRACKS` | Each track's `require` terms (title must contain one) and `exclude` terms (title must contain none). A job is sent if it passes **any** track. |
| `SENIORITY_EXCLUDE` | Senior / lead / manager / intern titles, dropped on every track. |
| `DOMAIN_EXCLUDE` | Wrong-field titles (sales, HR, software dev, etc.). The Data Centre track allows electrical, mechanical, maintenance, equipment and controls, since many DC technician roles are facilities-side. |
| `TARGET_COMPANIES` | Companies that get the ⭐ PRIORITY tag (and the only ones allowed for Penang on JobStreet). |
| `MIN_SALARY_MYR` | Drop a job only if it shows a salary below this. |
| `LINKEDIN_LOCATION` / `DISTANCE_MILES` | Search centre + radius (LinkedIn only accepts 5/10/25/50/75/100 mile steps). |
| `JOBSTREET_LOCATION_CONFIGS` | Which keywords run in which JobStreet location. |
| `TIME_WINDOW_SECONDS` | How far back each LinkedIn search looks (kept wider than the run interval). |
| `SEEN_RETENTION_DAYS` | How long a sent job is remembered. |

All filter terms match **whole words**, case-insensitively, so short terms are safe:
`"hr"` matches "HR Executive" but not "Threat Analyst", and `"soc"` matches "SOC
Analyst" but not "Associate". Hyphens and slashes in titles count as spaces, so
"Data-Centre" matches "data centre".

To change the check frequency, edit the `cron` line in
`.github/workflows/job_alert.yml`. GitHub Actions cron is in **UTC**; Malaysia is
UTC+8, so subtract 8 hours.

## If it stops sending anything

Usually LinkedIn changed their page's HTML class names. Open the Actions run logs.
If you see `Found 0 new matching job(s)` for several days in a row when you'd expect
matches, the CSS selectors in `fetch_jobs_linkedin()` likely need updating. If you
see `Sent 0, failed N`, check the Telegram secrets.
