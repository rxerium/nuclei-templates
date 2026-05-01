#!/usr/bin/env python3
"""
Phishing Template Validation Script
Validates nuclei phishing templates against official sites to ensure matchers are current.
"""

import os
import sys
import yaml
import json
import time
import requests
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re

# Constants
PHISHING_DIR = Path("http/osint/phishing")
REQUEST_DELAY = 1.5  # seconds between requests
REQUEST_TIMEOUT = 10  # seconds
MAX_RETRIES = 3
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
]

class ValidationResult:
    def __init__(self, template_name: str):
        self.template_name = template_name
        self.official_url = None
        self.title = None
        self.description = None
        self.current_matchers = []
        self.suggested_matchers = []
        self.status = "pending"  # pending, success, waf_blocked, error, match_failed
        self.error_message = None
        self.needs_update = False
        
    def to_dict(self):
        return {
            "template_name": self.template_name,
            "official_url": self.official_url,
            "title": self.title,
            "description": self.description,
            "current_matchers": self.current_matchers,
            "suggested_matchers": self.suggested_matchers,
            "status": self.status,
            "error_message": self.error_message,
            "needs_update": self.needs_update
        }


def fetch_page(url: str, retry_count: int = 0) -> Optional[Tuple[str, int, Dict]]:
    """Fetch a webpage with retry logic and WAF detection."""
    headers = {
        "User-Agent": USER_AGENTS[retry_count % len(USER_AGENTS)],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True)
        return response.text, response.status_code, dict(response.headers)
    except requests.exceptions.Timeout:
        if retry_count < MAX_RETRIES - 1:
            time.sleep(2 ** retry_count)  # exponential backoff
            return fetch_page(url, retry_count + 1)
        return None
    except requests.exceptions.SSLError:
        # Try with www. prefix if SSL fails
        if '://www.' not in url and retry_count == 0:
            parsed = urlparse(url)
            www_url = f"{parsed.scheme}://www.{parsed.netloc}{parsed.path}"
            return fetch_page(www_url, retry_count + 1)
        return None
    except Exception as e:
        # Try with www. prefix on connection errors
        if '://www.' not in url and retry_count == 0:
            parsed = urlparse(url)
            www_url = f"{parsed.scheme}://www.{parsed.netloc}{parsed.path}"
            return fetch_page(www_url, retry_count + 1)
        return None


def is_waf_blocked(status_code: int, headers: Dict, content: str) -> bool:
    """Detect if request was blocked by WAF/Cloudflare."""
    # Check for common WAF status codes
    if status_code in [403, 503, 429, 999]:
        return True
    
    # Check for Cloudflare
    if 'cf-ray' in headers or 'CF-RAY' in headers:
        if status_code != 200:
            return True
        if 'cloudflare' in content.lower() and 'checking your browser' in content.lower():
            return True
    
    # Check for other WAF signatures
    waf_signatures = [
        'access denied',
        'blocked by administrator',
        'firewall',
        'security check',
        'captcha',
        'incapsula',
        'imperva',
        'akamai',
        'rate limit exceeded'
    ]
    
    content_lower = content.lower()
    for sig in waf_signatures:
        if sig in content_lower and status_code != 200:
            return True
    
    return False


def extract_metadata(html: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract title and meta description from HTML."""
    soup = BeautifulSoup(html, 'html.parser')
    
    # Extract title
    title = None
    title_tag = soup.find('title')
    if title_tag:
        title = title_tag.get_text().strip()
    
    # Extract meta description
    description = None
    meta_desc = soup.find('meta', attrs={'name': 'description'})
    if meta_desc and meta_desc.get('content'):
        description = meta_desc.get('content').strip()
    
    # Fallback to Open Graph description
    if not description:
        og_desc = soup.find('meta', attrs={'property': 'og:description'})
        if og_desc and og_desc.get('content'):
            description = og_desc.get('content').strip()
    
    return title, description


def load_template(template_path: Path) -> Optional[Dict]:
    """Load and parse a YAML template."""
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading {template_path}: {e}")
        return None


def extract_current_matchers(template_data: Dict) -> List[str]:
    """Extract current word matchers from template."""
    matchers = []
    
    if 'http' not in template_data or not template_data['http']:
        return matchers
    
    for req in template_data['http']:
        if 'matchers' in req:
            for matcher in req['matchers']:
                if matcher.get('type') == 'word' and 'words' in matcher:
                    matchers.extend(matcher['words'])
    
    return matchers


def get_official_url(template_data: Dict) -> Optional[str]:
    """Extract official URL from template reference."""
    if 'info' not in template_data or 'reference' not in template_data['info']:
        return None
    
    refs = template_data['info']['reference']
    if isinstance(refs, list) and len(refs) > 0:
        url = refs[0] if refs[0].startswith('http') else f"https://{refs[0]}"
        # Add www. if not present and domain has no subdomain
        parsed = urlparse(url)
        if '://www.' not in url and parsed.netloc.count('.') == 1:
            url = f"{parsed.scheme}://www.{parsed.netloc}{parsed.path or ''}"
        return url
    
    return None


def validate_template(template_path: Path) -> ValidationResult:
    """Validate a single phishing template."""
    result = ValidationResult(template_path.stem)
    
    # Load template
    template_data = load_template(template_path)
    if not template_data:
        result.status = "error"
        result.error_message = "Failed to load template"
        return result
    
    # Extract current matchers
    result.current_matchers = extract_current_matchers(template_data)
    
    # Get official URL
    result.official_url = get_official_url(template_data)
    if not result.official_url:
        result.status = "error"
        result.error_message = "No official URL found in template"
        return result
    
    # Fetch official page
    print(f"  Fetching: {result.official_url}")
    fetch_result = fetch_page(result.official_url)
    
    if not fetch_result:
        result.status = "error"
        result.error_message = "Failed to fetch official site (timeout or connection error)"
        return result
    
    html, status_code, headers = fetch_result
    
    # Check for WAF blocking
    if is_waf_blocked(status_code, headers, html):
        result.status = "waf_blocked"
        result.error_message = f"WAF/Cloudflare blocked (status: {status_code})"
        return result
    
    # Extract metadata
    result.title, result.description = extract_metadata(html)
    
    if not result.title:
        result.status = "error"
        result.error_message = "No title found on official site"
        return result
    
    # Generate suggested matchers
    result.suggested_matchers = []
    
    # Title matcher (titles are in HTML body, not HTTP headers)
    result.suggested_matchers.append({
        "type": "word",
        "part": "body",
        "words": [result.title]
    })
    
    # Description/body matcher
    if result.description:
        # Shorten description if too long
        desc = result.description
        if len(desc) > 100:
            # Try to find a distinctive phrase
            sentences = desc.split('.')
            desc = sentences[0].strip() if sentences else desc[:80]
        
        result.suggested_matchers.append({
            "type": "word",
            "part": "body",
            "words": [desc]
        })
    else:
        # Fallback: try to extract a distinctive body phrase
        soup = BeautifulSoup(html, 'html.parser')
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        text = soup.get_text()
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if lines:
            # Use first substantial line as fallback
            for line in lines[:10]:
                if 10 < len(line) < 150 and not line.startswith('<'):
                    result.suggested_matchers.append({
                        "type": "word",
                        "part": "body",
                        "words": [line]
                    })
                    break
    
    # Check if current matchers match
    current_match = False
    for matcher in result.current_matchers:
        if matcher in html or matcher in result.title:
            current_match = True
            break
    
    if not current_match:
        result.status = "match_failed"
        result.needs_update = True
    else:
        # Check if we have only 1 matcher (needs second one)
        word_matcher_count = sum(1 for m in template_data['http'][0].get('matchers', []) if m.get('type') == 'word')
        if word_matcher_count < 2:
            result.status = "success"
            result.needs_update = True  # Need to add second matcher
        else:
            result.status = "success"
            result.needs_update = False
    
    return result


def generate_markdown_report(results: List[ValidationResult], output_path: Path):
    """Generate markdown validation report."""
    successful = [r for r in results if r.status == "success"]
    needs_update = [r for r in results if r.needs_update]
    waf_blocked = [r for r in results if r.status == "waf_blocked"]
    errors = [r for r in results if r.status == "error"]
    
    report = f"""# Phishing Template Validation Report

**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

## Summary

- **Total Templates:** {len(results)}
- **Successfully Validated:** {len(successful)}
- **Need Updates:** {len(needs_update)}
- **WAF/Cloudflare Blocked:** {len(waf_blocked)}
- **Errors:** {len(errors)}

---

## Templates Needing Updates

"""
    
    if needs_update:
        for result in needs_update:
            report += f"### {result.template_name}\n\n"
            report += f"**Official URL:** {result.official_url}\n\n"
            report += f"**Current Title:** `{result.title}`\n\n"
            if result.description:
                report += f"**Description:** {result.description}\n\n"
            report += f"**Current Matchers:**\n```yaml\n"
            for m in result.current_matchers:
                report += f"  - '{m}'\n"
            report += "```\n\n"
            report += f"**Status:** {result.status}\n\n"
            if result.error_message:
                report += f"**Issue:** {result.error_message}\n\n"
            report += "---\n\n"
    else:
        report += "*All templates are up to date!*\n\n"
    
    report += "## WAF/Cloudflare Blocked Sites\n\n"
    if waf_blocked:
        report += "The following sites could not be validated due to WAF/Cloudflare protection:\n\n"
        for result in waf_blocked:
            report += f"- **{result.template_name}**: {result.official_url} ({result.error_message})\n"
    else:
        report += "*No sites blocked by WAF/Cloudflare.*\n"
    
    report += "\n---\n\n## Errors\n\n"
    if errors:
        for result in errors:
            report += f"- **{result.template_name}**: {result.error_message}\n"
    else:
        report += "*No errors encountered.*\n"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n✓ Validation report written to: {output_path}")


def generate_waf_blocked_doc(results: List[ValidationResult], output_path: Path):
    """Generate WAF blocked sites documentation."""
    waf_blocked = [r for r in results if r.status == "waf_blocked"]
    
    doc = f"""# WAF/Cloudflare Blocked Phishing Templates

**Last Updated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

## Overview

These phishing templates reference official sites that are protected by WAF (Web Application Firewall) or Cloudflare, preventing automated validation.

**Total Blocked:** {len(waf_blocked)}

## Blocked Sites

"""
    
    if waf_blocked:
        for result in waf_blocked:
            doc += f"### {result.template_name}\n\n"
            doc += f"- **Official URL:** {result.official_url}\n"
            doc += f"- **Block Reason:** {result.error_message}\n"
            doc += f"- **Template Path:** `http/osint/phishing/{result.template_name}.yaml`\n\n"
    else:
        doc += "*No sites currently blocked.*\n"
    
    doc += """
## Validation Strategy

For WAF-blocked sites, manual validation is recommended:

1. Visit the official site manually
2. Extract the title and meta description
3. Update the template matchers accordingly
4. Test the template against known phishing samples (if available)

## Automation Notes

The GitHub Action workflow will skip these templates during automated validation to avoid repeated blocking.
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(doc)
    
    print(f"✓ WAF blocked sites documented in: {output_path}")


def generate_updates_json(results: List[ValidationResult], output_path: Path):
    """Generate JSON file with templates needing updates."""
    needs_update = [r for r in results if r.needs_update]
    
    updates = {
        "generated_at": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        "total_templates": len(results),
        "needs_update_count": len(needs_update),
        "templates": [r.to_dict() for r in needs_update]
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(updates, f, indent=2)
    
    print(f"✓ Update suggestions written to: {output_path}")


def main():
    """Main validation workflow."""
    print("=" * 80)
    print("Phishing Template Validation Script")
    print("=" * 80)
    
    # Find all phishing templates
    templates = sorted(PHISHING_DIR.glob("*.yaml"))
    print(f"\nFound {len(templates)} phishing templates to validate\n")
    
    results = []
    
    for i, template_path in enumerate(templates, 1):
        print(f"[{i}/{len(templates)}] Validating: {template_path.stem}")
        
        try:
            result = validate_template(template_path)
            results.append(result)
            
            # Status indicator
            status_icon = {
                "success": "✓",
                "waf_blocked": "🚫",
                "error": "✗",
                "match_failed": "⚠"
            }.get(result.status, "?")
            
            needs_update_text = " (needs update)" if result.needs_update else ""
            print(f"  {status_icon} Status: {result.status}{needs_update_text}")
        except Exception as e:
            print(f"  ✗ Critical error during validation: {e}")
            result = ValidationResult(template_path.stem)
            result.status = "error"
            result.error_message = f"Critical validation error: {str(e)}"
            results.append(result)
        
        # Rate limiting delay
        if i < len(templates):
            time.sleep(REQUEST_DELAY)
        
        print()
    
    # Generate reports
    print("\n" + "=" * 80)
    print("Generating Reports")
    print("=" * 80 + "\n")
    
    generate_markdown_report(results, Path("PHISHING_VALIDATION_REPORT.md"))
    generate_waf_blocked_doc(results, Path("phishing_waf_blocked.md"))
    generate_updates_json(results, Path("templates_to_update.json"))
    
    # Summary
    print("\n" + "=" * 80)
    print("Validation Complete")
    print("=" * 80)
    print(f"\nTotal: {len(results)}")
    print(f"  Success: {len([r for r in results if r.status == 'success'])}")
    print(f"  Needs Update: {len([r for r in results if r.needs_update])}")
    print(f"  WAF Blocked: {len([r for r in results if r.status == 'waf_blocked'])}")
    print(f"  Errors: {len([r for r in results if r.status == 'error'])}")
    
    # Exit code based on results
    if any(r.needs_update for r in results):
        sys.exit(1)  # Indicate updates needed
    sys.exit(0)


if __name__ == "__main__":
    main()
