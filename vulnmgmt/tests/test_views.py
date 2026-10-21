import time

import pytest
from django.urls import reverse

from vulnmgmt.models import Asset, AssetVulnerability, AuditLog, RemediationTask, User, Vulnerability
from vulnmgmt.scoring import breakdown_for

from .conftest import TEST_PASSWORD


@pytest.mark.django_db
@pytest.mark.parametrize('name', ['dashboard', 'finding_list', 'asset_list', 'vulnerability_list', 'task_list',
                                  'reports', 'comparison', 'about_scoring'])
def test_login_required(client, name):
    """FR1: nothing is visible without authentication."""
    response = client.get(reverse(name))
    assert response.status_code == 302 and reverse('login') in response.url


@pytest.mark.django_db
def test_login_and_audit(client, admin_user):
    response = client.post(reverse('login'), {'username': 'admin1', 'password': TEST_PASSWORD})
    assert response.status_code == 302
    assert AuditLog.objects.filter(action='LOGIN', user=admin_user).exists()
    client.logout()
    client.post(reverse('login'), {'username': 'admin1', 'password': 'wrong'})
    assert AuditLog.objects.filter(action='LOGIN_FAILED').exists()


@pytest.mark.django_db
def test_passwords_are_hashed(admin_user, analyst):
    """NFR 2: no plaintext passwords in the user table."""
    for user in User.objects.all():
        assert user.password != TEST_PASSWORD
        assert user.password.startswith(('pbkdf2_sha256$', 'argon2', 'bcrypt', 'scrypt'))


@pytest.mark.django_db
@pytest.mark.parametrize('name', ['dashboard', 'finding_list', 'asset_list', 'vulnerability_list', 'task_list',
                                  'reports', 'comparison', 'about_scoring', 'audit_log', 'nvd_import',
                                  'asset_create', 'finding_create', 'vulnerability_create'])
def test_pages_render_for_admin(admin_client, finding, name):
    finding.calculate_score()
    assert admin_client.get(reverse(name)).status_code == 200


@pytest.mark.django_db
def test_detail_pages_render(admin_client, finding):
    finding.calculate_score()
    task = finding.tasks.get()
    for url in [finding.get_absolute_url(), finding.asset.get_absolute_url(),
                finding.vulnerability.get_absolute_url(), reverse('task_edit', args=[task.pk]),
                reverse('export_findings_csv')]:
        assert admin_client.get(url).status_code == 200, url


@pytest.mark.django_db
@pytest.mark.parametrize('path,list_view', [
    ('/findings/999999/', 'finding_list'), ('/assets/999999/', 'asset_list'),
    ('/vulnerabilities/999999/', 'vulnerability_list'), ('/tasks/999999/', 'task_list'),
])
def test_stale_record_link_redirects_to_list(admin_client, path, list_view):
    """A link to a deleted record (e.g. after seed_demo --reset) lands on the current list, not a 404."""
    response = admin_client.get(path, follow=True)
    assert response.status_code == 200
    assert response.redirect_chain[-1][0] == reverse(list_view)
    assert 'no longer exists' in response.content.decode()


@pytest.mark.django_db
def test_analyst_cannot_manage_assets(analyst_client):
    response = analyst_client.get(reverse('asset_create'))
    assert response.status_code == 403 and 'Access denied' in response.content.decode()
    assert analyst_client.get(reverse('nvd_import')).status_code == 403
    assert analyst_client.get(reverse('audit_log')).status_code == 403


@pytest.mark.django_db
def test_admin_creates_asset_and_it_is_matched(admin_client, critical_cve, admin_user):
    response = admin_client.post(reverse('asset_create'), {
        'name': 'New DC', 'asset_type': 'Server', 'criticality': 'Critical', 'exposure': 'Internal',
        'software_keywords': 'microsoft:windows_server_2019'})
    assert response.status_code == 302
    asset = Asset.objects.get(name='New DC')
    av = AssetVulnerability.objects.get(asset=asset)
    assert av.risk_level in ('High', 'Critical')
    assert AuditLog.objects.filter(action='CREATE', object_type='Asset', user=admin_user).exists()


@pytest.mark.django_db
def test_state_chart_transitions(admin_client, finding):
    url = reverse('finding_transition', args=[finding.pk])
    admin_client.post(url, {'status': 'Resolved'})  # not allowed from Open
    finding.refresh_from_db()
    assert finding.status == 'Open'
    for status in ['Acknowledged', 'Risk Accepted', 'Closed']:
        admin_client.post(url, {'status': status, 'note': 'test'})
        finding.refresh_from_db()
        assert finding.status == status
    assert finding.allowed_transitions() == []


@pytest.mark.django_db
def test_assigning_task_moves_finding_into_remediation(admin_client, finding, analyst):
    finding.calculate_score()
    finding.status = 'Acknowledged'
    finding.save()
    task = finding.tasks.get()
    admin_client.post(reverse('task_edit', args=[task.pk]), {
        'title': task.title, 'assigned_to': analyst.pk, 'status': 'In Progress', 'due_date': '2026-12-01'})
    finding.refresh_from_db()
    assert finding.status == 'In Remediation'


@pytest.mark.django_db
def test_analyst_updates_only_own_tasks(analyst_client, analyst, finding):
    finding.calculate_score()
    task = finding.tasks.get()
    assert analyst_client.get(reverse('task_edit', args=[task.pk])).status_code == 403
    task.assigned_to = analyst
    task.save()
    response = analyst_client.post(reverse('task_edit', args=[task.pk]), {'status': 'Completed', 'notes': 'patched'})
    assert response.status_code == 302
    task.refresh_from_db()
    assert task.status == RemediationTask.Status.COMPLETED and task.completed_at


@pytest.mark.django_db
def test_audit_log_records_updates(admin_client, finance_server, admin_user):
    admin_client.post(reverse('asset_edit', args=[finance_server.pk]), {
        'name': finance_server.name, 'asset_type': 'Server', 'criticality': 'High', 'exposure': 'Internet',
        'software_keywords': finance_server.software_keywords})
    log = AuditLog.objects.get(action='UPDATE', object_type='Asset')
    assert 'criticality: Critical -> High' in log.details and log.user == admin_user
    # Regression (found in black-box test TC-11): untouched empty optional fields are not reported as changes.
    assert 'ip_address' not in log.details and 'owner' not in log.details


@pytest.mark.django_db
def test_dashboard_orders_by_smart_score(admin_client, finance_server, test_vm, critical_cve):
    low = AssetVulnerability.objects.create(asset=test_vm, vulnerability=critical_cve)
    high = AssetVulnerability.objects.create(asset=finance_server, vulnerability=critical_cve)
    low.calculate_score(), high.calculate_score()
    top = list(admin_client.get(reverse('dashboard')).context['top_findings'])
    assert top[0] == high and top[1] == low


@pytest.mark.django_db
def test_dashboard_list_5000_records_under_5_seconds(admin_client):
    """NFR 1: a prioritised list of 5,000 findings renders in under 5 seconds."""
    Asset.objects.bulk_create([Asset(name=f'A{i}', criticality='High') for i in range(50)])
    Vulnerability.objects.bulk_create(
        [Vulnerability(cve_id=f'CVE-2099-{i:05d}', cvss_score=round(1 + (i % 90) / 10, 1)) for i in range(100)])
    # MySQL does not return primary keys from bulk_create, so reload the rows.
    assets, vulns = list(Asset.objects.all()), list(Vulnerability.objects.all())
    rows = []
    for a in assets:
        for v in vulns:
            av = AssetVulnerability(asset=a, vulnerability=v)
            av.priority_score = float(v.cvss_score) * 9
            rows.append(av)
    AssetVulnerability.objects.bulk_create(rows)
    assert AssetVulnerability.objects.count() == 5000

    start = time.perf_counter()
    response = admin_client.get(reverse('finding_list'), {'per_page': 5000})
    elapsed = time.perf_counter() - start
    assert response.status_code == 200
    assert len(response.context['page'].object_list) == 5000
    assert elapsed < 5, f'took {elapsed:.2f}s'
