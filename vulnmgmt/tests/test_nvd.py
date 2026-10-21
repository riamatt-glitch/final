import pytest
import requests

from vulnmgmt.models import AssetVulnerability, Vulnerability
from vulnmgmt.nvd import NVDClient, NVDError, parse_cve
from vulnmgmt.services import import_from_nvd

NVD_CVE = {
    'id': 'CVE-2021-44228',
    'published': '2021-12-10T10:15:09.143',
    'lastModified': '2024-04-03T17:15:10.000',
    'cisaExploitAdd': '2021-12-10',
    'descriptions': [{'lang': 'es', 'value': 'otro'}, {'lang': 'en', 'value': 'Apache Log4j2 JNDI RCE.'}],
    'metrics': {
        'cvssMetricV31': [
            {'source': 'other@example.org', 'type': 'Secondary', 'cvssData': {'baseScore': 9.0, 'baseSeverity': 'CRITICAL', 'vectorString': 'X'}},
            {'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {
                'baseScore': 10.0, 'baseSeverity': 'CRITICAL',
                'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'}},
        ],
        'cvssMetricV2': [{'type': 'Primary', 'cvssData': {'baseScore': 9.3}, 'baseSeverity': 'HIGH'}],
    },
    'references': [{'url': 'https://example.org/patch', 'tags': ['Patch', 'Vendor Advisory']},
                   {'url': 'https://example.org/poc', 'tags': ['Exploit', 'Third Party Advisory']}],
    'configurations': [{'nodes': [{'cpeMatch': [
        {'vulnerable': True, 'criteria': 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'},
        {'vulnerable': False, 'criteria': 'cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*'},
    ]}]}],
}


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload, self.status_code, self.text = payload, status, ''

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, pages, status=200, failures=()):
        self.pages, self.status, self.calls = pages, status, []
        self.failures = list(failures)  # exceptions or status codes returned before the real pages

        self.served = 0

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(dict(params))
        if self.failures:
            failure = self.failures.pop(0)
            if isinstance(failure, Exception):
                raise failure
            return FakeResponse({}, failure)
        self.served += 1
        return FakeResponse(self.pages[self.served - 1], self.status)


def test_parse_cve_extracts_fields():
    rec = parse_cve(NVD_CVE)
    assert rec['cve_id'] == 'CVE-2021-44228'
    assert rec['description'] == 'Apache Log4j2 JNDI RCE.'
    assert rec['cvss_score'] == 10.0 and rec['cvss_version'] == '3.1'  # Primary NVD score preferred
    assert rec['severity'] == 'Critical'
    assert rec['exploit_available'] and rec['publicly_exploited'] and rec['patch_available']
    assert rec['cpe_matches'] == 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'
    assert rec['published_date'].year == 2021


def test_parse_cve_without_metrics():
    rec = parse_cve({'id': 'CVE-2099-0001', 'descriptions': [], 'metrics': {}})
    assert rec['cvss_score'] is None and not rec['exploit_available']


def test_client_paginates_and_honours_max_results():
    page = lambda n: {'totalResults': 5, 'vulnerabilities': [{'cve': {**NVD_CVE, 'id': f'CVE-2021-{i}'}} for i in range(n)]}
    session = FakeSession([page(2), page(2), page(1)])
    client = NVDClient(api_key='k', base_url='http://nvd.test', session=session)
    client.delay = 0
    ids = [r['cve_id'] for r in client.search(keyword='log4j', max_results=4)]
    assert len(ids) == 4
    assert [c['startIndex'] for c in session.calls] == [0, 2]
    assert session.calls[0]['keywordSearch'] == 'log4j'


def _fast_client(session):
    client = NVDClient(api_key='k', base_url='http://nvd.test', session=session, backoff=0)
    client.delay = 0
    return client


def test_client_retries_slow_or_unavailable_nvd():
    page = {'totalResults': 1, 'vulnerabilities': [{'cve': NVD_CVE}]}
    session = FakeSession([page], failures=[requests.Timeout('slow'), 503])
    records = list(_fast_client(session).search(cve_id='CVE-2021-44228'))
    assert [r['cve_id'] for r in records] == ['CVE-2021-44228']
    assert len(session.calls) == 3


def test_client_gives_up_after_retries():
    session = FakeSession([], failures=[requests.Timeout('slow')] * 3)
    with pytest.raises(NVDError, match='after 3 attempts'):
        list(_fast_client(session).search(cve_id='CVE-2021-44228'))


def test_client_reports_rate_limit():
    client = NVDClient(api_key='', base_url='http://nvd.test', session=FakeSession([{}], status=403))
    with pytest.raises(NVDError, match='rate limit'):
        list(client.search(cve_id='CVE-2021-44228'))


@pytest.mark.django_db
def test_import_matches_assets_and_scores(test_vm, finance_server):
    session = FakeSession([{'totalResults': 1, 'vulnerabilities': [{'cve': NVD_CVE}]}])
    client = NVDClient(api_key='k', base_url='http://nvd.test', session=session)
    result = import_from_nvd(cve_id='CVE-2021-44228', client=client)
    assert result.created == 1 and result.findings_created == 1
    av = AssetVulnerability.objects.get()
    assert av.asset == test_vm  # log4j keyword matched; the Windows server did not
    assert av.priority_score > 0 and av.scored_at is not None

    # Re-importing updates rather than duplicates.
    session.pages.append({'totalResults': 1, 'vulnerabilities': [{'cve': NVD_CVE}]})
    result = import_from_nvd(cve_id='CVE-2021-44228', client=client)
    assert result.updated == 1 and Vulnerability.objects.count() == 1 and AssetVulnerability.objects.count() == 1
