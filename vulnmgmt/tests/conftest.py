import pytest

from vulnmgmt.models import Asset, AssetVulnerability, User, Vulnerability

TEST_PASSWORD = 'Test-Pass-for-RBVMS-1'


@pytest.fixture
def admin_user(db):
    return User.objects.create_user('admin1', password=TEST_PASSWORD, role=User.Role.ADMINISTRATOR)


@pytest.fixture
def analyst(db):
    return User.objects.create_user('analyst1', password=TEST_PASSWORD, role=User.Role.ANALYST)


@pytest.fixture
def admin_client(client, admin_user):
    client.force_login(admin_user)
    return client


@pytest.fixture
def analyst_client(client, analyst):
    client.force_login(analyst)
    return client


@pytest.fixture
def finance_server(db):
    return Asset.objects.create(name='Finance DB Server', criticality='Critical', exposure='Internet',
                                software_keywords='microsoft:windows_server_2019')


@pytest.fixture
def test_vm(db):
    return Asset.objects.create(name='Test VM', criticality='Low', exposure='Internal',
                                software_keywords='apache:log4j')


@pytest.fixture
def critical_cve(db):
    return Vulnerability.objects.create(
        cve_id='CVE-2025-41230', cvss_score=9.8, exploit_available=True, publicly_exploited=True,
        patch_available=False, cpe_matches='cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*')


@pytest.fixture
def finding(finance_server, critical_cve):
    return AssetVulnerability.objects.create(asset=finance_server, vulnerability=critical_cve)
