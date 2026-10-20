"""
Smart Priority Score engine.

The score (0-100) combines the CVSS base score with organisational context, as described in
Section 1.6 of the proposal. Each factor is normalised to 0..1 and multiplied by its weight;
the weights sum to 100 so the result is directly a 0-100 score.

The calculation is a pure function of the stored data, so the same inputs always give the same
score (non-functional requirement 3 in Section 2.4.1).
"""

from dataclasses import dataclass
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal

from django.conf import settings
from django.db import transaction
from django.utils import timezone

DEFAULT_WEIGHTS = {
    'cvss': 30,                 # CVSS severity score
    'asset_criticality': 25,    # business importance of the affected asset
    'exploit_available': 10,    # public exploit / PoC exists
    'publicly_exploited': 10,   # actively exploited in the wild (CISA KEV)
    'exposure': 10,             # internal / DMZ / internet-facing
    'affected_systems': 5,      # how many assets share the vulnerability
    'patch_unavailable': 5,     # no patch means compensating controls are needed
    'remediation_pending': 5,   # remediation has not yet progressed
}

CRITICALITY_FACTOR = {'Low': 0.25, 'Medium': 0.5, 'High': 0.75, 'Critical': 1.0}
EXPOSURE_FACTOR = {'Internal': 0.3, 'DMZ': 0.7, 'Internet': 1.0}
REMEDIATION_FACTOR = {
    'Open': 1.0, 'Acknowledged': 1.0, 'In Remediation': 0.5,
    'Resolved': 0.0, 'Risk Accepted': 0.0, 'Closed': 0.0,
}
# A vulnerability on this many or more assets gets the full "affected systems" factor.
AFFECTED_SYSTEMS_CAP = 5

# Lower bound of each risk band.
RISK_THRESHOLDS = [(80, 'Critical'), (60, 'High'), (40, 'Medium'), (0, 'Low')]

# Days allowed to remediate, by risk level, for automatically generated tasks.
REMEDIATION_SLA_DAYS = {'Critical': 7, 'High': 14, 'Medium': 30}


def get_weights():
    weights = {**DEFAULT_WEIGHTS, **getattr(settings, 'SMART_PRIORITY_WEIGHTS', {})}
    total = sum(weights.values())
    if total != 100:
        raise ValueError(f'Smart Priority Score weights must sum to 100 (got {total}).')
    return weights


@dataclass(frozen=True)
class ScoreBreakdown:
    factors: dict       # factor name -> normalised value 0..1
    contributions: dict  # factor name -> points contributed
    score: float
    risk_level: str


def compute_factors(cvss_score, asset_criticality, exploit_available, publicly_exploited,
                    exposure, affected_systems, patch_available, remediation_status):
    return {
        'cvss': min(max(float(cvss_score or 0) / 10.0, 0.0), 1.0),
        'asset_criticality': CRITICALITY_FACTOR.get(asset_criticality, 0.5),
        'exploit_available': 1.0 if exploit_available else 0.0,
        'publicly_exploited': 1.0 if publicly_exploited else 0.0,
        'exposure': EXPOSURE_FACTOR.get(exposure, 0.3),
        'affected_systems': min(max(affected_systems, 1), AFFECTED_SYSTEMS_CAP) / AFFECTED_SYSTEMS_CAP,
        'patch_unavailable': 0.0 if patch_available else 1.0,
        'remediation_pending': REMEDIATION_FACTOR.get(remediation_status, 1.0),
    }


def compute_weighted_score(factors, weights=None):
    weights = weights or get_weights()
    contributions = {name: round(weights[name] * value, 2) for name, value in factors.items()}
    raw = Decimal(str(sum(weights[name] * value for name, value in factors.items())))
    score = float(raw.quantize(Decimal('0.1'), rounding=ROUND_HALF_UP))
    return min(max(score, 0.0), 100.0), contributions


def classify_risk_level(score):
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return 'Low'


def breakdown_for(asset_vulnerability):
    """Compute the score for an AssetVulnerability without saving anything."""
    av = asset_vulnerability
    vuln, asset = av.vulnerability, av.asset
    affected = vuln.asset_vulnerabilities.exclude(
        status__in=['Resolved', 'Risk Accepted', 'Closed']).count()
    if av.pk is None or not av.is_active:
        affected += 1
    factors = compute_factors(
        cvss_score=vuln.cvss_score,
        asset_criticality=asset.criticality,
        exploit_available=vuln.exploit_available,
        publicly_exploited=vuln.publicly_exploited,
        exposure=asset.exposure,
        affected_systems=affected,
        patch_available=vuln.patch_available,
        remediation_status=av.status,
    )
    score, contributions = compute_weighted_score(factors)
    return ScoreBreakdown(factors, contributions, score, classify_risk_level(score))


@transaction.atomic
def calculate_and_save(asset_vulnerability, user=None, create_task=True):
    """
    calculateScore() as specified in Section 3.7:
    sets priority_score (0-100) and risk_level, creates an Open RemediationTask for
    Medium/High/Critical findings that have none, and records an AuditLog entry.
    """
    from .models import AuditLog, RemediationTask

    av = asset_vulnerability
    result = breakdown_for(av)
    previous = (float(av.priority_score), av.risk_level) if av.scored_at else None

    av.priority_score = Decimal(str(result.score))
    av.risk_level = result.risk_level
    av.scored_at = timezone.now()
    av._skip_audit = True
    av.save()

    task = None
    if (create_task and av.is_active and result.risk_level in REMEDIATION_SLA_DAYS
            and not av.tasks.filter(status__in=[RemediationTask.Status.OPEN,
                                                RemediationTask.Status.IN_PROGRESS]).exists()):
        task = RemediationTask(
            asset_vulnerability=av,
            title=f'Remediate {av.vulnerability.cve_id} on {av.asset.name}',
            status=RemediationTask.Status.OPEN,
            due_date=av.detected_date + timedelta(days=REMEDIATION_SLA_DAYS[result.risk_level]),
            created_by=user if user is not None and user.is_authenticated else None,
        )
        task._skip_audit = True
        task.save()

    if previous != (result.score, result.risk_level):
        details = f'Smart Priority Score {result.score} ({result.risk_level})'
        if previous:
            details += f'; previously {previous[0]} ({previous[1]})'
        if task:
            details += f'; remediation task #{task.pk} created, due {task.due_date}'
        AuditLog.record_action('SCORE_CALCULATED', av, details, user=user)
    return result


def rescore_queryset(queryset, user=None):
    count = 0
    for av in queryset.select_related('asset', 'vulnerability'):
        calculate_and_save(av, user=user)
        count += 1
    return count
