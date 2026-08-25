"""
cve_lookup.py
AI_KAVACH — CVE Lookup Tool
— Harshal's machine

Tool function: lookup_cve()

Called by local LLM via the TOOLS registry after check_sqli_patterns()
identifies attack types and the agent wants CVE details to enrich findings.

Data source:
    NIST National Vulnerability Database (NVD) API v2
    API docs:    https://nvd.nist.gov/developers/vulnerabilities
    API key:     https://nvd.nist.gov/developers/request-an-api-key
    Free tier:   5 requests per 30 seconds (no key)
    With key:    50 requests per 30 seconds

    API key goes in config.py as NVD_API_KEY.
    Without a key the tool still works — just rate limited.

Caching strategy:
    Every successful CVE lookup is saved to a local JSON cache file
    at NVD_CACHE_DIR (defined in config.py, default: data/nvd_cache/).
    On subsequent calls for the same CVE, the cache is returned instantly
    without hitting the NVD API. This means:
        - Tool works offline after first lookup of each CVE
        - No rate limit issues on repeated runs
        - Cache persists across agent restarts

    Cache expiry: 7 days. Stale entries are re-fetched automatically.

Keyword search:
    Beyond exact CVE ID lookup, the tool also supports semantic keyword
    search against cached CVEs. local LLM can search for
    "SQLi PHP login" and get relevant CVEs without knowing the exact ID.

Does NOT:
    - Modify any system files
    - Execute any commands
    - Perform active scanning
    - Access anything other than the NVD API and local cache

Registration in tools.py:
    from cve_lookup import lookup_cve
    TOOLS = {
        "lookup_cve": lookup_cve,
        ...
    }

local LLM calls it like this:
    Exact CVE lookup:
    {
      "action": "lookup_cve",
      "action_input": {"cve_id": "CVE-2021-44228"}
    }

    Keyword search:
    {
      "action": "lookup_cve",
      "action_input": {"cve_id": "search:sql injection php authentication bypass"}
    }

Config variables needed in config.py:
    NVD_API_KEY      = "REPLACE_WITH_YOUR_NVD_API_KEY"
    NVD_CACHE_DIR    = "data/nvd_cache"
    NVD_CACHE_EXPIRY = 604800   # 7 days in seconds
    NVD_TIMEOUT      = 15       # seconds per API call
    NVD_MAX_RESULTS  = 5        # max CVEs returned per keyword search
"""

import os
import re
import json
import time
import logging
from pathlib import Path
from datetime import datetime, timezone

import httpx

from app.config import PLATFORM_NAME

logger = logging.getLogger(f"{PLATFORM_NAME}.tools.cve_lookup")


try:
    from app.config import NVD_API_KEY
except ImportError:
    NVD_API_KEY = ""
    logger.warning("NVD_API_KEY not found in config.py — rate limited to 5 req/30s")

try:
    from app.config import NVD_CACHE_DIR
except ImportError:
    NVD_CACHE_DIR = "data/nvd_cache"

try:
    from app.config import NVD_CACHE_EXPIRY
except ImportError:
    NVD_CACHE_EXPIRY = 604800  

try:
    from app.config import NVD_TIMEOUT
except ImportError:
    NVD_TIMEOUT = 15

try:
    from app.config import NVD_MAX_RESULTS
except ImportError:
    NVD_MAX_RESULTS = 5






NVD_BASE_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_URL         = f"{NVD_BASE_URL}?cveId="
NVD_KEYWORD_URL     = f"{NVD_BASE_URL}?keywordSearch="


SEVERITY_LABELS = {
    (9.0, 10.0): "CRITICAL",
    (7.0,  8.9): "HIGH",
    (4.0,  6.9): "MEDIUM",
    (0.1,  3.9): "LOW",
    (0.0,  0.0): "NONE",
}


_CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


SEARCH_PREFIX = "search:"






def _cache_path(cve_id: str) -> Path:
    """Return the local cache file path for a CVE ID."""
    safe_id = cve_id.upper().replace("/", "_")
    return Path(NVD_CACHE_DIR) / f"{safe_id}.json"


def _cache_read(cve_id: str) -> dict | None:
    """
    Read CVE data from local cache.
    Returns None if not cached or cache is expired.
    """
    path = _cache_path(cve_id)
    if not path.exists():
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            cached = json.load(f)

        cached_at = cached.get("_cached_at", 0)
        age = time.time() - cached_at

        if age > NVD_CACHE_EXPIRY:
            logger.debug(f"Cache expired for {cve_id} (age: {age:.0f}s)")
            return None

        logger.debug(f"Cache hit for {cve_id} (age: {age:.0f}s)")
        return cached

    except (json.JSONDecodeError, KeyError, OSError) as e:
        logger.warning(f"Cache read failed for {cve_id}: {e}")
        return None


def _cache_write(cve_id: str, data: dict) -> None:
    """Write CVE data to local cache with timestamp."""
    path = _cache_path(cve_id)
    Path(NVD_CACHE_DIR).mkdir(parents=True, exist_ok=True)

    data["_cached_at"] = time.time()
    data["_cached_date"] = datetime.now(timezone.utc).isoformat()

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.debug(f"Cached {cve_id} to {path}")
    except OSError as e:
        logger.warning(f"Cache write failed for {cve_id}: {e}")


def _cache_list_all() -> list:
    """Return list of all cached CVE IDs."""
    cache_dir = Path(NVD_CACHE_DIR)
    if not cache_dir.exists():
        return []
    return [f.stem for f in cache_dir.glob("CVE-*.json")]






def _severity_label(score: float) -> str:
    """Convert CVSS score to severity label string."""
    for (low, high), label in SEVERITY_LABELS.items():
        if low <= score <= high:
            return label
    return "UNKNOWN"


def _parse_nvd_response(cve_item: dict) -> dict:
    """
    Parse a single CVE item from NVD API v2 response format
    into a clean, flat dictionary for local LLM to reason over.

    NVD API v2 response structure reference:
    https://nvd.nist.gov/developers/vulnerabilities

    Args:
        cve_item: Single item from response["vulnerabilities"] list

    Returns:
        Clean flat dict with all forensically relevant CVE fields
    """
    cve = cve_item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    
    descriptions = cve.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "No description available")

    
    published  = cve.get("published", "Unknown")
    modified   = cve.get("lastModified", "Unknown")

    
    cvss_v3_score    = None
    cvss_v3_vector   = None
    cvss_v3_severity = None
    attack_vector    = None
    attack_complexity = None
    privileges_required = None
    user_interaction = None
    scope            = None
    confidentiality  = None
    integrity        = None
    availability     = None

    metrics = cve.get("metrics", {})

    
    for cvss_key in ("cvssMetricV31", "cvssMetricV30"):
        cvss_list = metrics.get(cvss_key, [])
        if cvss_list:
            primary = next(
                (m for m in cvss_list if m.get("type") == "Primary"),
                cvss_list[0]
            )
            cvss_data = primary.get("cvssData", {})
            cvss_v3_score    = cvss_data.get("baseScore")
            cvss_v3_vector   = cvss_data.get("vectorString")
            cvss_v3_severity = cvss_data.get("baseSeverity")
            attack_vector    = cvss_data.get("attackVector")
            attack_complexity = cvss_data.get("attackComplexity")
            privileges_required = cvss_data.get("privilegesRequired")
            user_interaction = cvss_data.get("userInteraction")
            scope            = cvss_data.get("scope")
            confidentiality  = cvss_data.get("confidentialityImpact")
            integrity        = cvss_data.get("integrityImpact")
            availability     = cvss_data.get("availabilityImpact")
            break

    
    cvss_v2_score = None
    if cvss_v3_score is None:
        for v2 in metrics.get("cvssMetricV2", []):
            cvss_v2_score = v2.get("cvssData", {}).get("baseScore")
            break

    final_score    = cvss_v3_score or cvss_v2_score or 0.0
    final_severity = cvss_v3_severity or _severity_label(float(final_score))

    
    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    
    configurations = cve.get("configurations", [])
    affected_products = []
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    cpe = cpe_match.get("criteria", "")
                    
                    
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor  = parts[3]
                        product = parts[4]
                        version = parts[5] if len(parts) > 5 else "*"
                        if product != "*":
                            affected_products.append(
                                f"{vendor}/{product} {version}".strip()
                            )
            if len(affected_products) >= 10:
                break

    
    seen = set()
    unique_products = []
    for p in affected_products:
        if p not in seen:
            seen.add(p)
            unique_products.append(p)
    affected_products = unique_products[:10]

    
    references = cve.get("references", [])
    ref_urls = []
    
    priority_tags = {"Patch", "Exploit", "Vendor Advisory", "Third Party Advisory"}
    priority_refs = [r for r in references if set(r.get("tags", [])) & priority_tags]
    other_refs    = [r for r in references if r not in priority_refs]

    for ref in (priority_refs + other_refs)[:5]:
        url  = ref.get("url", "")
        tags = ref.get("tags", [])
        if url:
            ref_urls.append({"url": url, "tags": tags})

    
    
    
    epss_score = None
    epss_percentile = None

    
    exploit_available = any(
        "Exploit" in ref.get("tags", []) for ref in references
    )

    
    parsed = {
        
        "cve_id":               cve_id,
        "published":            published,
        "last_modified":        modified,

        
        "description":          description,

        
        "cvss_score":           final_score,
        "cvss_severity":        final_severity,
        "cvss_vector":          cvss_v3_vector,
        "cvss_version":         "3.1" if "cvssMetricV31" in metrics else
                                "3.0" if "cvssMetricV30" in metrics else "2.0",

        
        "attack_vector":        attack_vector,
        "attack_complexity":    attack_complexity,
        "privileges_required":  privileges_required,
        "user_interaction":     user_interaction,
        "scope":                scope,

        
        "confidentiality_impact": confidentiality,
        "integrity_impact":       integrity,
        "availability_impact":    availability,

        
        "cwe_ids":              cwe_ids,
        "affected_products":    affected_products,

        
        "exploit_available":    exploit_available,
        "epss_score":           epss_score,
        "epss_percentile":      epss_percentile,

        
        "references":           ref_urls,

        
        "nvd_url":              f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }

    return parsed






def _build_headers() -> dict:
    """Build NVD API request headers."""
    headers = {"Accept": "application/json"}
    if NVD_API_KEY and NVD_API_KEY != "REPLACE_WITH_YOUR_NVD_API_KEY":
        headers["apiKey"] = NVD_API_KEY
    return headers


def _fetch_cve_from_api(cve_id: str) -> dict | None:
    """
    Fetch a single CVE from NIST NVD API v2 by exact CVE ID.

    Args:
        cve_id: CVE identifier e.g. CVE-2021-44228

    Returns:
        Parsed CVE dict on success, None on failure
    """
    url = f"{NVD_CVE_URL}{cve_id.upper()}"
    logger.info(f"Fetching {cve_id} from NVD API: {url}")

    try:
        with httpx.Client(timeout=NVD_TIMEOUT) as client:
            response = client.get(url, headers=_build_headers())
            response.raise_for_status()
            data = response.json()

    except httpx.TimeoutException:
        logger.warning(f"NVD API timeout for {cve_id}")
        return None
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.info(f"{cve_id} not found in NVD")
        else:
            logger.warning(f"NVD API HTTP error for {cve_id}: {e.response.status_code}")
        return None
    except Exception as e:
        logger.warning(f"NVD API error for {cve_id}: {e}")
        return None

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        logger.info(f"No vulnerability data returned for {cve_id}")
        return None

    return _parse_nvd_response(vulnerabilities[0])


def _search_nvd_by_keyword(keywords: str) -> list:
    """
    Search NVD API v2 by keyword.
    Returns list of parsed CVE dicts, up to NVD_MAX_RESULTS.

    Args:
        keywords: Search terms e.g. "sql injection php authentication"
    """
    url = f"{NVD_KEYWORD_URL}{keywords}&resultsPerPage={NVD_MAX_RESULTS}"
    logger.info(f"NVD keyword search: {keywords}")

    try:
        with httpx.Client(timeout=NVD_TIMEOUT) as client:
            response = client.get(url, headers=_build_headers())
            response.raise_for_status()
            data = response.json()

    except httpx.TimeoutException:
        logger.warning(f"NVD keyword search timeout: {keywords}")
        return []
    except httpx.HTTPStatusError as e:
        logger.warning(f"NVD keyword search HTTP error: {e.response.status_code}")
        return []
    except Exception as e:
        logger.warning(f"NVD keyword search error: {e}")
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    results = []

    for vuln in vulnerabilities[:NVD_MAX_RESULTS]:
        parsed = _parse_nvd_response(vuln)
        if parsed:
            results.append(parsed)
            
            _cache_write(parsed["cve_id"], parsed)

    return results






def _format_single_cve(cve: dict) -> str:
    """
    Format a single parsed CVE dict into a readable string for local LLM.
    """
    lines = [
        "═" * 60,
        f"CVE DETAILS — {cve['cve_id']}",
        "═" * 60,
        f"",
        f"SEVERITY:      {cve['cvss_severity']} (CVSS {cve['cvss_score']}/10.0)",
        f"CVSS VERSION:  {cve['cvss_version']}",
        f"VECTOR:        {cve['cvss_vector'] or 'Not available'}",
        f"PUBLISHED:     {cve['published'][:10] if cve['published'] != 'Unknown' else 'Unknown'}",
        f"LAST MODIFIED: {cve['last_modified'][:10] if cve['last_modified'] != 'Unknown' else 'Unknown'}",
        f"",
        f"DESCRIPTION:",
        f"  {cve['description']}",
        f"",
    ]

    
    if any([cve.get("attack_vector"), cve.get("attack_complexity")]):
        lines += [
            f"ATTACK CHARACTERISTICS:",
            f"  Vector:              {cve.get('attack_vector', 'N/A')}",
            f"  Complexity:          {cve.get('attack_complexity', 'N/A')}",
            f"  Privileges required: {cve.get('privileges_required', 'N/A')}",
            f"  User interaction:    {cve.get('user_interaction', 'N/A')}",
            f"  Scope:               {cve.get('scope', 'N/A')}",
            f"",
        ]

    
    if any([cve.get("confidentiality_impact"), cve.get("integrity_impact")]):
        lines += [
            f"IMPACT:",
            f"  Confidentiality: {cve.get('confidentiality_impact', 'N/A')}",
            f"  Integrity:       {cve.get('integrity_impact', 'N/A')}",
            f"  Availability:    {cve.get('availability_impact', 'N/A')}",
            f"",
        ]

    
    if cve.get("cwe_ids"):
        lines += [f"CWE CLASSIFICATION: {', '.join(cve['cwe_ids'])}", f""]

    
    lines += [
        f"EXPLOIT AVAILABLE: {'YES — treat as active threat' if cve['exploit_available'] else 'Not confirmed in NVD'}",
        f"",
    ]

    
    if cve.get("affected_products"):
        lines += ["AFFECTED PRODUCTS:"]
        for p in cve["affected_products"][:5]:
            lines.append(f"  - {p}")
        if len(cve["affected_products"]) > 5:
            lines.append(f"  ... and {len(cve['affected_products']) - 5} more")
        lines.append("")

    
    if cve.get("references"):
        lines += ["KEY REFERENCES:"]
        for ref in cve["references"][:3]:
            tags = ", ".join(ref.get("tags", [])) or "Reference"
            lines.append(f"  [{tags}] {ref['url']}")
        lines.append("")

    lines += [
        f"NVD LINK: {cve['nvd_url']}",
        f"",
    ]

    
    score = float(cve.get("cvss_score", 0))
    if score >= 9.0:
        lines.append(
            "Code Analysis RELEVANCE: CRITICAL severity. If this CVE applies to the "
            "target system, the incident should be treated as a confirmed "
            "critical breach. Escalate immediately."
        )
    elif score >= 7.0:
        lines.append(
            "Code Analysis RELEVANCE: HIGH severity. Exploitation of this CVE would "
            "represent a significant security incident. Include in Code Analysis report "
            "as a high-priority finding."
        )
    elif score >= 4.0:
        lines.append(
            "Code Analysis RELEVANCE: MEDIUM severity. Include in Code Analysis report but "
            "prioritise higher-severity findings first."
        )
    else:
        lines.append(
            "Code Analysis RELEVANCE: LOW severity. Note in Code Analysis report as a minor finding."
        )

    return "\n".join(lines)


def _format_search_results(results: list, keywords: str) -> str:
    """Format multiple CVE search results for local LLM."""
    if not results:
        return (
            f"[CVE SEARCH] No results found for: '{keywords}'\n"
            f"Try different keywords or look up a specific CVE ID directly."
        )

    header = [
        "═" * 60,
        f"CVE KEYWORD SEARCH RESULTS — '{keywords}'",
        f"Found: {len(results)} CVE(s)",
        "═" * 60,
        "",
    ]

    sections = []
    for cve in results:
        sections.append(_format_single_cve(cve))

    return "\n".join(header) + "\n\n".join(sections)






def _lookup_cve_impl(cve_id: str) -> str:
    """Internal CVE lookup implementation."""
    if not cve_id or not cve_id.strip():
        return (
            "[CVE LOOKUP ERROR]\n"
            "cve_id parameter is empty.\n"
            "Pass a CVE ID like 'CVE-2021-44228' or "
            "a keyword search like 'search:sql injection php'."
        )

    cve_id = cve_id.strip()

    
    if cve_id.lower().startswith(SEARCH_PREFIX):
        keywords = cve_id[len(SEARCH_PREFIX):].strip()
        if not keywords:
            return (
                "[CVE LOOKUP ERROR]\n"
                "Keyword search is empty after 'search:' prefix.\n"
                "Example: search:sql injection php authentication"
            )

        logger.info(f"Keyword search mode: '{keywords}'")

        
        results = _search_nvd_by_keyword(keywords)

        if not results:
            
            cached_ids = _cache_list_all()
            fallback_results = []
            keywords_lower = keywords.lower()
            for cid in cached_ids[:50]:
                cached = _cache_read(cid)
                if cached and keywords_lower in cached.get("description", "").lower():
                    fallback_results.append(cached)
                    if len(fallback_results) >= NVD_MAX_RESULTS:
                        break

            if fallback_results:
                logger.info(f"Using {len(fallback_results)} cached results for keyword search")
                return _format_search_results(fallback_results, keywords) + \
                       "\n\n[NOTE: Results from local cache — NVD API returned no results]"

        return _format_search_results(results, keywords)

    
    
    cve_id = cve_id.upper()

    
    if not _CVE_PATTERN.match(cve_id):
        return (
            f"[CVE LOOKUP ERROR]\n"
            f"'{cve_id}' is not a valid CVE identifier.\n"
            f"Expected format: CVE-YYYY-NNNNN (e.g. CVE-2021-44228)\n"
            f"For keyword search use: search:your keywords here"
        )

    logger.info(f"lookup_cve called: {cve_id}")

    
    cached = _cache_read(cve_id)
    if cached:
        cached["_from_cache"] = True
        output = _format_single_cve(cached)
        return output + "\n[Source: local cache]"

    
    parsed = _fetch_cve_from_api(cve_id)

    if parsed:
        _cache_write(cve_id, parsed)
        output = _format_single_cve(parsed)
        return output + "\n[Source: NIST NVD API v2]"

    
    not_found_msg = (
        f"[CVE NOT FOUND]\n"
        f"CVE ID: {cve_id}\n"
        f"\n"
        f"Not found in NVD API or local cache.\n"
        f"\n"
        f"Possible reasons:\n"
        f"  1. CVE ID is incorrect — double check the ID from pattern scanner\n"
        f"  2. CVE is very recent and not yet in NVD (NVD can lag by days)\n"
        f"  3. NVD API is temporarily unreachable\n"
        f"  4. CVE was rejected or marked as disputed by NVD\n"
        f"\n"
        f"Suggestions:\n"
        f"  - Try: search:sql injection [technology name] for related CVEs\n"
        f"  - Check manually: https://nvd.nist.gov/vuln/detail/{cve_id}\n"
        f"  - Check MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}\n"
        f"\n"
        f"Continue Code Analysis analysis without CVE enrichment for this finding."
    )

    return not_found_msg


def lookup_cve(cve_id: str) -> str:
    """Public CVE lookup wrapper with graceful failure semantics."""
    try:
        return _lookup_cve_impl(cve_id)
    except Exception as e:
        logger.exception(f"lookup_cve unexpected failure for input='{cve_id}': {e}")
        return (
            "[CVE LOOKUP ERROR]\n"
            "Unexpected internal error while processing CVE lookup.\n"
            "Continue assessment without CVE enrichment for this step.\n"
            f"Details: {str(e)[:300]}"
        )








COMMON_WEB_CVES = [
    
    "CVE-2022-32250",  
    "CVE-2023-23752",  
    "CVE-2022-21661",  

    
    "CVE-2022-3590",   
    "CVE-2023-2745",   

    
    "CVE-2021-44228",  
    "CVE-2022-22965",  
    "CVE-2021-41773",  

    
    "CVE-2022-40684",  
    "CVE-2023-20198",  

    
    "CVE-2022-0847",   
    "CVE-2021-3129",   

    
    "CVE-2019-19781",  
    "CVE-2021-22986",  

    
    "CVE-2018-1000840", 
]


def warm_common_cves(cves: list = None) -> dict:
    """
    Pre-populate the local cache with common web CVEs.
    Run this once during setup so the agent has data offline.

    Args:
        cves: List of CVE IDs to warm. Defaults to COMMON_WEB_CVES.

    Returns:
        Dict with success/failure counts.

    Usage:
        python cve_lookup.py --warm-cache
    """
    target_cves = cves or COMMON_WEB_CVES
    results = {"success": 0, "failed": 0, "cached": 0}

    print(f"[WARM CACHE] Pre-caching {len(target_cves)} CVEs...")

    for cve_id in target_cves:
        
        if _cache_read(cve_id):
            print(f"  [SKIP] {cve_id} already cached")
            results["cached"] += 1
            continue

        parsed = _fetch_cve_from_api(cve_id)
        if parsed:
            _cache_write(cve_id, parsed)
            print(f"  [OK]   {cve_id} — {parsed['cvss_severity']} ({parsed['cvss_score']})")
            results["success"] += 1
        else:
            print(f"  [FAIL] {cve_id}")
            results["failed"] += 1

        
        delay = 0.7 if NVD_API_KEY else 6.5
        time.sleep(delay)

    print(f"\n[WARM CACHE] Complete: {results['success']} fetched, "
          f"{results['cached']} already cached, {results['failed']} failed")
    return results






if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="AI_KAVACH CVE Lookup Tool — ",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cve_lookup.py --cve CVE-2021-44228
  python cve_lookup.py --cve "search:sql injection php login"
  python cve_lookup.py --warm-cache
  python cve_lookup.py --cache-stats
        """
    )
    parser.add_argument("--cve",        help="CVE ID or search:keywords to look up")
    parser.add_argument("--warm-cache", action="store_true", help="Pre-cache common web CVEs")
    parser.add_argument("--cache-stats",action="store_true", help="Show cache statistics")

    args = parser.parse_args()

    if args.warm_cache:
        warm_common_cves()

    elif args.cache_stats:
        cached = _cache_list_all()
        print(f"[CACHE STATS]")
        print(f"  Cache directory: {NVD_CACHE_DIR}")
        print(f"  Cached CVEs:     {len(cached)}")
        print(f"  Cache expiry:    {NVD_CACHE_EXPIRY // 86400} days")
        if cached:
            print(f"  Sample IDs:      {', '.join(cached[:5])}")

    elif args.cve:
        print(f"[TEST] Looking up: {args.cve}\n")
        result = lookup_cve(args.cve)
        print(result)

    else:
        
        print("[TEST] Default test — CVE-2021-44228 (Log4Shell)\n")
        result = lookup_cve("CVE-2021-44228")
        print(result)

        print("\n[TEST] Keyword search test\n")
        result = lookup_cve("search:sql injection authentication bypass")
        print(result)

        print("\n[TEST] Invalid CVE test\n")
        result = lookup_cve("NOT-A-CVE")
        print(result)