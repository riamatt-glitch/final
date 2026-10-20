import pytest

from vulnmgmt.models import AssetVulnerability, AuditLog, RemediationTask, Vulnerability
from vulnmgmt.scoring import (DEFAULT_WEIGHTS, breakdown_for, classify_risk_level, compute_factors,
                              compute_weighted_score)


def _factors(**overrides):
    base = dict(cvss_score=9.8, asset_criticality='Critical', exploit_available=True, publicly_exploited=True,
                exposure='Internet', affected_systems=1, patch_available=False, remediation_status='Open')
    base.update(overrides)
    return compute_factors(**base)


def test_weights_sum_to_100():
    assert sum(DEFAULT_WEIGHTS.values()) == 100


def test_score_is_bounded():
    worst, _ = compute_weighted_score(_factors(cvss_score=10, affected_systems=99))
    best, _ = compute_weighted_score(_factors(cvss_score=0, asset_criticality='Low', exploit_available=False,
                                              publicly_exploited=False, exposure='Internal',
                                              patch_available=True, remediation_status='Closed'))
    assert worst == 100.0
    assert 0 <= best < 20


@pytest.mark.parametrize('score,level', [
    (100, 'Critical'), (80, 'Critical'), (79.9, 'High'), (60, 'High'),
    (59.9, 'Medium'), (40, 'Medium'), (39.9, 'Low'), (0, 'Low'),
])
def test_classify_risk_level(score, level):
    assert classify_risk_level(score) == level


def test_asset_criticality_changes_priority_for_same_cve():
    """The core claim of the project: the same CVE ranks differently on different assets."""
    critical, _ = compute_weighted_score(_factors(asset_criticality='Critical'))
    low, _ = compute_weighted_score(_factors(asset_criticality='Low', exposure='Internal'))
    assert critical - low >= 20


def test_medium_cvss_on_critical_asset_outranks_high_cvss_on_low_asset():
    medium_on_critical, _ = compute_weighted_score(_factors(cvss_score=6.5, asset_criticality='Critical',
                                                            exposure='Internet'))
    high_on_low, _ = compute_weighted_score(_factors(cvss_score=9.1, asset_criticality='Low', exposure='Internal',
                                                     exploit_available=False, publicly_exploited=False))
    assert medium_on_critical > high_on_low


@pytest.mark.django_db
def test_score_is_repeatable(finding):
    """NFR 3: identical inputs give an identical score on at least three runs."""
    scores = {finding.calculate_score().score for _ in range(3)}
    finding.refresh_from_db()
    assert len(scores) == 1
    assert float(finding.priority_score) == scores.pop()


@pytest.mark.django_db
def test_calculate_score_postconditions(finding, admin_user):
    """Section 3.7 post-conditions for AssetVulnerability::calculateScore."""
    result = finding.calculate_score(user=admin_user)
    finding.refresh_from_db()
    assert 0 <= float(finding.priority_score) <= 100
    assert finding.risk_level == classify_risk_level(float(finding.priority_score)) == result.risk_level == 'Critical'
    task = finding.tasks.get()
    assert task.status == RemediationTask.Status.OPEN
    assert (task.due_date - finding.detected_date).days == 7
    assert AuditLog.objects.filter(action='SCORE_CALCULATED', object_id=str(finding.pk), user=admin_user).exists()


@pytest.mark.django_db
def test_no_task_for_low_risk(test_vm):
    vuln = Vulnerability.objects.create(cve_id='CVE-2000-0001', cvss_score=2.0, patch_available=True)
    av = AssetVulnerability.objects.create(asset=test_vm, vulnerability=vuln)
    assert av.calculate_score().risk_level == 'Low'
    assert not av.tasks.exists()


@pytest.mark.django_db
def test_no_duplicate_open_tasks(finding):
    finding.calculate_score()
    finding.calculate_score()
    assert finding.tasks.count() == 1


@pytest.mark.django_db
def test_changing_asset_criticality_rescores(finding):
    finding.calculate_score()
    before = float(AssetVulnerability.objects.get(pk=finding.pk).priority_score)
    finding.asset.criticality = 'Low'
    finding.asset.save()
    after = float(AssetVulnerability.objects.get(pk=finding.pk).priority_score)
    assert after < before


@pytest.mark.django_db
def test_remediation_progress_lowers_score(finding):
    open_score = finding.calculate_score().score
    finding.status = 'In Remediation'
    finding.save()
    assert finding.calculate_score().score < open_score
    assert breakdown_for(finding).factors['remediation_pending'] == 0.5
