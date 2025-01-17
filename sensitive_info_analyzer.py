import requests
import re
import argparse

def fetch_web_archive(domain):
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "collapse": "urlkey",
        "output": "text",
        "fl": "original"
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.text.splitlines()
    else:
        print(f"Error fetching data from Web Archive: {response.status_code}")
        return []

def fetch_virus_total(domain, api_key):
    url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {
        "apikey": api_key,
        "domain": domain
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json().get("detected_urls", [])
    else:
        print(f"Error fetching data from VirusTotal: {response.status_code}")
        return []

def fetch_otx(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
    params = {"limit": 500, "page": 1}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return [url_data.get("url") for url_data in response.json().get("url_list", [])]
    else:
        print(f"Error fetching data from OTX: {response.status_code}")
        return []

def filter_sensitive_files(urls):
    sensitive_patterns = re.compile(r'\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$', re.IGNORECASE)
    return [url for url in urls if sensitive_patterns.search(url)]


def main():
    parser = argparse.ArgumentParser(description="Script to analyze sensitive information from domains.")
    parser.add_argument("-d", "--domain", required=True, help="Domain to analyze (e.g., example.com)")
    parser.add_argument("-k", "--apikey", required=True, help="VirusTotal API key")
    args = parser.parse_args()

    domain = args.domain
    vt_api_key = args.apikey

    print("Fetching data from Web Archive...")
    web_archive_urls = fetch_web_archive(domain)

    print("Fetching data from VirusTotal...")
    virus_total_urls = fetch_virus_total(domain, vt_api_key)

    print("Fetching data from OTX...")
    otx_urls = fetch_otx(domain)

    all_urls = set(web_archive_urls + virus_total_urls + otx_urls)

    print("Filtering sensitive files...")
    sensitive_files = filter_sensitive_files(all_urls)

    if sensitive_files:
        print("Found sensitive files:")
        for file in sensitive_files:
            print(file)
    else:
        print("No sensitive files found.")

if __name__ == "__main__":
    main()
