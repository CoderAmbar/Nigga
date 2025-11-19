import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cve(product_name, version=None):
    """
    Search NVD for CVEs related to a software product.
    product_name: "Apache"
    version: "2.4.49"
    """

    params = {
        "keywordSearch": product_name,
        "resultsPerPage": 10
    }

    if version:
        params["keywordSearch"] = f"{product_name} {version}"

    try:
        r = requests.get(NVD_API, params=params, timeout=8)
        data = r.json()

        out = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve")
            if not cve:
                continue

            out.append({
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value"),
                "severity": cve.get("metrics", {})
            })

        return out

    except Exception as e:
        return {"error": str(e)}
