"""
Client for the National Vulnerability Database (NVD) CVE API 2.0.

https://nvd.nist.gov/developers/vulnerabilities
Respects NVD's published rate limits: 5 requests / 30 s without an API key,
50 requests / 30 s with one.
"""

import time
from datetime import datetime, timedelta, timezone as dt_timezone

import requests
from django.conf import settings
from django.utils.dateparse import parse_datetime

RESULTS_PER_PAGE = 100
EXPLOIT_TAGS = {'exploit'}
PATCH_TAGS = {'patch', 'vendor advisory', 'mitigation'}


class NVDError(Exception):
    pass


class NVDClient:
    def __init__(self, api_key=None, base_url=None, session=None, timeout=30):
        self.api_key = api_key if api_key is not None else settings.NVD_API_KEY
        self.base_url = base_url or settings.NVD_API_URL
        self.session = session or requests.Session()
        self.timeout = timeout
        self.delay = 0.6 if self.api_key else 6.0
        self._last_request = 0.0

    def _get(self, params):
        wait = self.delay - (time.monotonic() - self._last_request)
        if self._last_request and wait > 0:
            time.sleep(wait)
        headers = {'apiKey': self.api_key} if self.api_key else {}
        try:
            response = self.session.get(self.base_url, params=params, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise NVDError(f'Could not reach the NVD API: {exc}') from exc
        finally:
            self._last_request = time.monotonic()
        if response.status_code in (403, 429):
            raise NVDError('NVD API rate limit reached. Wait 30 seconds or configure NVD_API_KEY.')
        if response.status_code != 200:
            raise NVDError(f'NVD API returned HTTP {response.status_code}: {response.text[:200]}')
        return response.json()

    def search(self, keyword=None, cve_id=None, days=None, max_results=100, kev_only=False):
        """Yield parsed CVE records matching the given criteria."""
        params = {'resultsPerPage': min(RESULTS_PER_PAGE, max_results)}
        if cve_id:
            params['cveId'] = cve_id.strip().upper()
        if keyword:
            params['keywordSearch'] = keyword
        if kev_only:
            params['hasKev'] = ''
        if days:
            end = datetime.now(dt_timezone.utc)
            start = end - timedelta(days=min(days, 120))  # NVD allows at most a 120-day window
            params['pubStartDate'] = start.strftime('%Y-%m-%dT%H:%M:%S.000')
            params['pubEndDate'] = end.strftime('%Y-%m-%dT%H:%M:%S.000')

        start_index, returned = 0, 0
        while returned < max_results:
            params['startIndex'] = start_index
            data = self._get(params)
            items = data.get('vulnerabilities', [])
            for item in items:
                if returned >= max_results:
                    break
                yield parse_cve(item.get('cve', {}))
                returned += 1
            start_index += len(items)
            if not items or start_index >= data.get('totalResults', 0):
                break


def _pick_cvss(metrics):
    """Prefer CVSS v3.1, then v4.0, v3.0, v2; prefer the NVD 'Primary' score within a version."""
    for key, version in (('cvssMetricV31', '3.1'), ('cvssMetricV40', '4.0'),
                         ('cvssMetricV30', '3.0'), ('cvssMetricV2', '2.0')):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
        data = entry.get('cvssData', {})
        severity = data.get('baseSeverity') or entry.get('baseSeverity', '')
        return data.get('baseScore'), version, data.get('vectorString', ''), severity
    return None, '', '', ''


def _collect_cpes(configurations):
    cpes = []
    for config in configurations or []:
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if match.get('vulnerable', True) and match.get('criteria'):
                    cpes.append(match['criteria'])
    return sorted(set(cpes))


def parse_cve(cve):
    """Convert one NVD 'cve' object into a dict of Vulnerability field values."""
    description = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
    score, version, vector, severity = _pick_cvss(cve.get('metrics', {}))
    tags = {t.lower() for ref in cve.get('references', []) for t in ref.get('tags', [])}
    return {
        'cve_id': cve.get('id', ''),
        'description': description,
        'cvss_score': score,
        'cvss_version': version,
        'cvss_vector': vector,
        'severity': (severity or '').title(),
        'exploit_available': bool(tags & EXPLOIT_TAGS) or bool(cve.get('cisaExploitAdd')),
        'publicly_exploited': bool(cve.get('cisaExploitAdd')),
        'patch_available': bool(tags & PATCH_TAGS),
        'cpe_matches': '\n'.join(_collect_cpes(cve.get('configurations'))),
        'published_date': parse_datetime(cve['published'] + ('' if cve['published'].endswith('Z') else 'Z'))
        if cve.get('published') else None,
        'last_modified': parse_datetime(cve['lastModified'] + ('' if cve['lastModified'].endswith('Z') else 'Z'))
        if cve.get('lastModified') else None,
        'source': 'NVD',
    }
