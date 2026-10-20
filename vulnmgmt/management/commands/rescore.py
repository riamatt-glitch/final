from django.core.management.base import BaseCommand

from vulnmgmt.models import AssetVulnerability
from vulnmgmt.scoring import rescore_queryset


class Command(BaseCommand):
    help = 'Recalculate the Smart Priority Score for every finding.'

    def handle(self, *args, **opts):
        count = rescore_queryset(AssetVulnerability.objects.all())
        self.stdout.write(self.style.SUCCESS(f'Rescored {count} findings.'))
