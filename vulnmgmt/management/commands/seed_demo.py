"""
Load a fabricated demonstration organisation (Section 1.8: no real organisation's data is used).

Assets, users and lifecycle states are invented. Vulnerability records are well-known public CVEs.
By default they are loaded from a built-in sample so the demo works offline; pass --live to fetch the
authoritative records for the same CVE IDs from the NVD API instead.
"""

import os
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from vulnmgmt.audit import reset_current_user, set_current_user
from vulnmgmt.models import Asset, AssetVulnerability, RemediationTask, User, Vulnerability
from vulnmgmt.nvd import NVDClient, NVDError
from vulnmgmt.scoring import REMEDIATION_SLA_DAYS
from vulnmgmt.services import import_records

DEMO_PASSWORD_DEFAULT = 'Demo-Pass-2026!'

USERS = [
    ('j.ncube', 'Joseph', 'Ncube', User.Role.ADMINISTRATOR),
    ('t.moyo', 'Tumelo', 'Moyo', User.Role.ANALYST),
    ('k.sebina', 'Kagiso', 'Sebina', User.Role.ANALYST),
]

ASSETS = [
    ('Finance DB Server', 'Database', 'Critical', 'Internal', '10.0.10.5', 'Finance',
     'microsoft:windows_server_2019, microsoft:sql_server'),
    ('Domain Controller', 'Server', 'Critical', 'Internal', '10.0.0.10', 'IT Operations',
     'microsoft:windows_server_2019'),
    ('Perimeter Firewall', 'Network Device', 'Critical', 'Internet', '196.0.2.1', 'IT Operations',
     'paloaltonetworks:pan-os'),
    ('Customer Web Portal', 'Application', 'High', 'Internet', '196.0.2.20', 'Client Services',
     'apache:http_server, apache:log4j, vmware:spring_framework, openbsd:openssh'),
    ('Remote Access Gateway', 'Network Device', 'High', 'Internet', '196.0.2.30', 'IT Operations',
     'citrix:netscaler'),
    ('Email & Collaboration', 'Cloud Service', 'High', 'Internet', None, 'IT Operations',
     'microsoft:outlook, microsoft:365_apps'),
    ('File Transfer Server', 'Server', 'High', 'DMZ', '172.16.0.15', 'Underwriting',
     'progress:moveit_transfer, openssl:openssl'),
    ('Claims Processing App', 'Application', 'High', 'Internal', '10.0.20.8', 'Claims',
     'oracle:jdk, apache:log4j, haxx:curl'),
    ('HR Workstation 07', 'Workstation', 'Medium', 'Internal', '10.0.30.107', 'Human Resources',
     'microsoft:windows_10, microsoft:outlook, oracle:jdk'),
    ('Legacy Claims Archive', 'Server', 'Medium', 'Internal', '10.0.20.40', 'Claims',
     'microsoft:windows_server_2008'),
    ('Dev / Test VM', 'Server', 'Low', 'Internal', '10.0.99.12', 'IT Development',
     'apache:log4j, openbsd:openssh, haxx:curl, sudo_project:sudo, openssl:openssl, apache:http_server'),
]

# Offline sample of public CVEs. Values are representative; use --live for authoritative NVD data.
SAMPLE_CVES = [
    ('CVE-2021-44228', 10.0, 'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints, allowing remote code execution (Log4Shell).', True, True, True, 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'),
    ('CVE-2020-1472', 10.0, 'Netlogon elevation of privilege vulnerability allowing an attacker to obtain domain administrator access (Zerologon).', True, True, True, 'cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*\ncpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*'),
    ('CVE-2024-3400', 10.0, 'Command injection in the GlobalProtect feature of PAN-OS allows an unauthenticated attacker to execute code with root privileges on the firewall.', True, True, True, 'cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*'),
    ('CVE-2019-0708', 9.8, 'Remote Desktop Services remote code execution vulnerability (BlueKeep).', True, True, True, 'cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*\ncpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*'),
    ('CVE-2023-34362', 9.8, 'SQL injection in MOVEit Transfer web application allowing unauthenticated access to the database.', True, True, True, 'cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*'),
    ('CVE-2022-22965', 9.8, 'Spring MVC or Spring WebFlux application on JDK 9+ vulnerable to remote code execution via data binding (Spring4Shell).', True, True, True, 'cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*'),
    ('CVE-2023-23397', 9.8, 'Microsoft Outlook elevation of privilege vulnerability via crafted reminder that leaks NTLM hashes.', True, True, True, 'cpe:2.3:a:microsoft:outlook:2016:*:*:*:*:*:*:*\ncpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:*:*'),
    ('CVE-2023-38545', 9.8, 'Heap buffer overflow in curl SOCKS5 proxy handshake.', False, False, True, 'cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*'),
    ('CVE-2023-4966', 9.4, 'Sensitive information disclosure in NetScaler ADC and Gateway configured as a gateway or AAA virtual server (Citrix Bleed).', True, True, True, 'cpe:2.3:o:citrix:netscaler_application_delivery_controller_firmware:*:*:*:*:*:*:*:*\ncpe:2.3:o:citrix:netscaler_gateway_firmware:*:*:*:*:*:*:*:*'),
    ('CVE-2021-34527', 8.8, 'Windows Print Spooler remote code execution vulnerability (PrintNightmare).', True, True, True, 'cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*\ncpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*'),
    ('CVE-2024-6387', 8.1, 'Signal handler race condition in OpenSSH server (sshd) allowing unauthenticated remote code execution (regreSSHion).', True, False, True, 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*'),
    ('CVE-2021-3156', 7.8, 'Heap-based buffer overflow in Sudo allowing privilege escalation to root (Baron Samedit).', True, True, True, 'cpe:2.3:a:sudo_project:sudo:*:*:*:*:*:*:*:*'),
    ('CVE-2021-41773', 7.5, 'Path traversal in Apache HTTP Server 2.4.49 allowing access to files outside the document root.', True, True, True, 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'),
    ('CVE-2022-21449', 7.5, 'Oracle Java SE ECDSA signature verification flaw allowing forged signatures (Psychic Signatures).', True, False, True, 'cpe:2.3:a:oracle:jdk:17:*:*:*:*:*:*:*'),
    ('CVE-2022-0778', 7.5, 'Infinite loop in OpenSSL BN_mod_sqrt() when parsing certificates, causing denial of service.', False, False, True, 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*'),
    ('CVE-2023-48795', 5.9, 'SSH transport protocol prefix truncation attack weakening channel integrity (Terrapin).', True, False, True, 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*'),
    ('CVE-2023-38546', 3.7, 'Cookie injection in libcurl when duplicating easy handles with no file.', False, False, True, 'cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*'),
]


def _severity(score):
    return 'Critical' if score >= 9 else 'High' if score >= 7 else 'Medium' if score >= 4 else 'Low'


class Command(BaseCommand):
    help = 'Load a fabricated demonstration organisation with users, assets and scored findings.'

    def add_arguments(self, parser):
        parser.add_argument('--live', action='store_true', help='Fetch the CVE records from the NVD API.')
        parser.add_argument('--reset', action='store_true', help='Delete existing assets, CVEs and findings first.')

    def handle(self, *args, **opts):
        password = os.environ.get('DEMO_PASSWORD', DEMO_PASSWORD_DEFAULT)
        admin = None
        for username, first, last, role in USERS:
            user, created = User.objects.get_or_create(
                username=username, defaults={'first_name': first, 'last_name': last, 'role': role,
                                             'email': f'{username}@example.org',
                                             'is_staff': role == User.Role.ADMINISTRATOR})
            if created:
                user.set_password(password)
                user.save()
            if role == User.Role.ADMINISTRATOR:
                admin = user
        token = set_current_user(admin)
        try:
            self._load(opts, admin)
        finally:
            reset_current_user(token)

    @transaction.atomic
    def _load(self, opts, admin):
        if opts['reset']:
            AssetVulnerability.objects.all().delete()
            Vulnerability.objects.all().delete()
            Asset.objects.all().delete()

        for name, atype, crit, exposure, ip, owner, keywords in ASSETS:
            Asset.objects.update_or_create(name=name, defaults={
                'asset_type': atype, 'criticality': crit, 'exposure': exposure, 'ip_address': ip,
                'owner': owner, 'software_keywords': keywords,
                'description': 'Fabricated demonstration asset (Kgori Insurance Brokers scenario).'})

        if opts['live']:
            records = []
            client = NVDClient()
            for cve_id, *_rest in SAMPLE_CVES:
                self.stdout.write(f'Fetching {cve_id} from NVD...')
                try:
                    records.extend(client.search(cve_id=cve_id, max_results=1))
                except NVDError as exc:
                    raise CommandError(str(exc))
        else:
            records = [{
                'cve_id': cve, 'cvss_score': score, 'cvss_version': '3.1', 'severity': _severity(score),
                'description': desc, 'exploit_available': exploit, 'publicly_exploited': kev,
                'patch_available': patch, 'cpe_matches': cpes, 'source': 'Sample',
            } for cve, score, desc, exploit, kev, patch, cpes in SAMPLE_CVES]

        result = import_records(records, user=admin)
        self._simulate_lifecycle(admin)
        self.stdout.write(self.style.SUCCESS(
            f'Demo loaded: {Asset.objects.count()} assets, {result.created + result.updated} CVEs, '
            f'{AssetVulnerability.objects.count()} scored findings.'))
        self.stdout.write('Demo users: ' + ', '.join(u for u, *_ in USERS) +
                          ' (password from DEMO_PASSWORD, or the default in seed_demo.py).')

    def _simulate_lifecycle(self, admin):
        """Spread detection dates and move some findings through the state chart so the dashboard is realistic."""
        today = timezone.localdate()
        analysts = list(User.objects.filter(role=User.Role.ANALYST).order_by('username'))
        findings = list(AssetVulnerability.objects.select_related('vulnerability', 'asset').order_by('id'))
        for i, av in enumerate(findings):
            av.detected_date = today - timedelta(days=(i * 3) % 40)
            AssetVulnerability.objects.filter(pk=av.pk).update(detected_date=av.detected_date)
            if av.risk_level in REMEDIATION_SLA_DAYS:
                av.tasks.update(due_date=av.detected_date + timedelta(days=REMEDIATION_SLA_DAYS[av.risk_level]))

            step = i % 6
            if step >= 1:
                av.status = 'Acknowledged'
            if step in (2, 3) and analysts:
                av.status = 'In Remediation'
                av.tasks.filter(status='Open').update(assigned_to=analysts[i % len(analysts)], status='In Progress')
            if step == 3:
                av.status = 'Resolved'
                av.tasks.update(status='Completed', completed_at=timezone.now())
            if step == 4 and av.risk_level == 'Low':
                av.status = 'Risk Accepted'
                av.notes = 'Low-value test system; accepted until decommissioning.'
            av.save()
            av.calculate_score(user=admin)
