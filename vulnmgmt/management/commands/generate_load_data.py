"""Generate synthetic findings to test the dashboard performance requirement (Section 2.4.1: 5,000 records < 5 s)."""

import random

from django.core.management.base import BaseCommand
from django.db import transaction

from vulnmgmt.models import Asset, AssetVulnerability, Vulnerability
from vulnmgmt.scoring import breakdown_for


class Command(BaseCommand):
    help = 'Create N synthetic, scored findings (fabricated LOADTEST CVE IDs) for performance testing.'

    def add_arguments(self, parser):
        parser.add_argument('--count', type=int, default=5000)
        parser.add_argument('--assets', type=int, default=50)
        parser.add_argument('--clear', action='store_true', help='Remove previously generated load-test data.')

    @transaction.atomic
    def handle(self, *args, **opts):
        if opts['clear']:
            AssetVulnerability.objects.filter(vulnerability__source='LoadTest').delete()
            Vulnerability.objects.filter(source='LoadTest').delete()
            Asset.objects.filter(name__startswith='LoadTest Asset').delete()
            self.stdout.write('Load-test data removed.')
            return
        rng = random.Random(42)
        crits = ['Low', 'Medium', 'High', 'Critical']
        exposures = ['Internal', 'DMZ', 'Internet']
        assets = [Asset.objects.get_or_create(name=f'LoadTest Asset {i:03d}', defaults={
            'criticality': rng.choice(crits), 'exposure': rng.choice(exposures)})[0] for i in range(opts['assets'])]
        per_asset = -(-opts['count'] // len(assets))
        vulns = Vulnerability.objects.bulk_create([
            Vulnerability(cve_id=f'LOADTEST-{i:06d}', cvss_score=round(rng.uniform(1, 10), 1),
                          exploit_available=rng.random() < .3, publicly_exploited=rng.random() < .05,
                          patch_available=rng.random() < .8, source='LoadTest',
                          description='Synthetic record for performance testing.')
            for i in range(per_asset)], ignore_conflicts=True)
        vulns = list(Vulnerability.objects.filter(source='LoadTest')[:per_asset])
        rows = []
        for asset in assets:
            for vuln in vulns:
                if len(rows) >= opts['count']:
                    break
                av = AssetVulnerability(asset=asset, vulnerability=vuln)
                result = breakdown_for(av)
                av.priority_score, av.risk_level = result.score, result.risk_level
                rows.append(av)
        AssetVulnerability.objects.bulk_create(rows, ignore_conflicts=True, batch_size=1000)
        self.stdout.write(self.style.SUCCESS(f'Created up to {len(rows)} synthetic findings.'))
