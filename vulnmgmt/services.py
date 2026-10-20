"""Application services: importing CVEs and matching them to assets."""

from dataclasses import dataclass, field

from django.db import transaction

from .models import Asset, AssetVulnerability, AuditLog, Vulnerability
from .nvd import NVDClient
from .scoring import rescore_queryset


@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    findings_created: int = 0
    cve_ids: list = field(default_factory=list)


def upsert_vulnerability(record):
    """Create or update a Vulnerability from a parsed NVD record. Returns (obj, created)."""
    cve_id = record['cve_id']
    defaults = {k: v for k, v in record.items() if k != 'cve_id'}
    return Vulnerability.objects.update_or_create(cve_id=cve_id, defaults=defaults)


def match_vulnerability(vulnerability, assets=None, user=None):
    """Link a vulnerability to every asset whose software keywords appear in its CPE list."""
    assets = assets if assets is not None else Asset.objects.exclude(software_keywords='')
    new_links = []
    for asset in assets:
        if vulnerability.affects(asset):
            av, created = AssetVulnerability.objects.get_or_create(asset=asset, vulnerability=vulnerability)
            if created:
                new_links.append(av)
    if new_links:
        # The "affected systems" factor changes for every finding of this CVE, so rescore them all.
        rescore_queryset(vulnerability.asset_vulnerabilities.all(), user=user)
    return new_links


def match_asset(asset, user=None):
    """Link an asset to every already-imported vulnerability it is affected by."""
    created = []
    for vuln in Vulnerability.objects.exclude(cpe_matches=''):
        created.extend(match_vulnerability(vuln, assets=[asset], user=user))
    return created


@transaction.atomic
def import_records(records, user=None):
    result = ImportResult()
    for record in records:
        if not record.get('cve_id'):
            continue
        vuln, created = upsert_vulnerability(record)
        result.created += created
        result.updated += not created
        result.cve_ids.append(vuln.cve_id)
        result.findings_created += len(match_vulnerability(vuln, user=user))
        if not created:
            rescore_queryset(vuln.asset_vulnerabilities.all(), user=user)
    AuditLog.record_action(
        'NVD_IMPORT', None,
        f'{result.created} created, {result.updated} updated, '
        f'{result.findings_created} new asset findings', user=user)
    return result


def import_from_nvd(keyword=None, cve_id=None, days=None, max_results=50, kev_only=False,
                    user=None, client=None):
    client = client or NVDClient()
    records = list(client.search(keyword=keyword, cve_id=cve_id, days=days,
                                 max_results=max_results, kev_only=kev_only))
    return import_records(records, user=user)
