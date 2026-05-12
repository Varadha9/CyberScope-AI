import urllib.request
import json
import re
import threading

_cache = {}
_lock = threading.Lock()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _query_nvd(keyword, max_results=5):
    """Query NVD CVE database for a keyword. Returns list of CVE dicts."""
    try:
        url = f"{NVD_API}?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage={max_results}"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberScope-AI/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break
            # Get CVSS score
            score = 0.0
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss = m.get("cvssData", {})
                    score = cvss.get("baseScore", 0.0)
                    severity = cvss.get("baseSeverity", m.get("baseSeverity", "UNKNOWN"))
                    break
            if cve_id:
                cves.append({
                    "id": cve_id,
                    "description": desc,
                    "score": score,
                    "severity": severity,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
        return sorted(cves, key=lambda x: x["score"], reverse=True)
    except Exception as e:
        return []


def lookup_cves(services: dict, max_per_service=3):
    """
    Given a services dict {port: {name, product, version}},
    look up CVEs for each detected product+version.
    Returns list of {port, product, cves: [...]}
    """
    results = []
    seen_queries = set()

    for port, svc in services.items():
        if not isinstance(svc, dict):
            continue
        product = svc.get("product", "").strip()
        version = svc.get("version", "").strip()
        name    = svc.get("name", "").strip()

        # Build search query — product+version is most specific
        if product and version:
            query = f"{product} {version}"
        elif product:
            query = product
        elif name and name not in ("tcpwrapped", "unknown", ""):
            query = name
        else:
            continue

        # Normalize query
        query = re.sub(r"\s+", " ", query).strip()
        if not query or query in seen_queries:
            continue
        seen_queries.add(query)

        with _lock:
            if query in _cache:
                cves = _cache[query]
            else:
                cves = _query_nvd(query, max_results=max_per_service)
                _cache[query] = cves

        if cves:
            results.append({
                "port": port,
                "product": product or name,
                "version": version,
                "query": query,
                "cves": cves[:max_per_service],
            })

    # Sort by highest CVE score
    results.sort(key=lambda x: max((c["score"] for c in x["cves"]), default=0), reverse=True)
    return results


def get_max_cvss(cve_results):
    """Return the highest CVSS score across all CVE results."""
    scores = [c["score"] for r in cve_results for c in r["cves"]]
    return max(scores, default=0.0)
