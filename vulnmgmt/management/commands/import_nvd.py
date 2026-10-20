from django.core.management.base import BaseCommand, CommandError

from vulnmgmt.nvd import NVDError
from vulnmgmt.services import import_from_nvd


class Command(BaseCommand):
    help = 'Import CVE records from the NVD API 2.0, match them to assets and score them. ' \
           'Suitable for scheduling (e.g. Windows Task Scheduler / cron).'

    def add_arguments(self, parser):
        parser.add_argument('--cve', help='A single CVE ID, e.g. CVE-2021-44228')
        parser.add_argument('--keyword', help='Keyword search, e.g. "apache http server"')
        parser.add_argument('--days', type=int, help='CVEs published in the last N days (max 120)')
        parser.add_argument('--kev', action='store_true', help='Only CISA Known Exploited Vulnerabilities')
        parser.add_argument('--max', type=int, default=100, help='Maximum number of CVEs to import')

    def handle(self, *args, **opts):
        if not any([opts['cve'], opts['keyword'], opts['days'], opts['kev']]):
            raise CommandError('Give at least one of --cve, --keyword, --days or --kev.')
        try:
            result = import_from_nvd(keyword=opts['keyword'], cve_id=opts['cve'], days=opts['days'],
                                     kev_only=opts['kev'], max_results=opts['max'])
        except NVDError as exc:
            raise CommandError(str(exc))
        self.stdout.write(self.style.SUCCESS(
            f'{result.created} created, {result.updated} updated, {result.findings_created} new asset findings.'))
