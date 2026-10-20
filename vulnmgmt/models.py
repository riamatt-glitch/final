"""
Data model for the Risk-Based Vulnerability Assessment and Management System.

The classes mirror the Class Diagram in Chapter 3 (Fig 5):
User, Asset, Vulnerability, AssetVulnerability (association class holding the
Smart Priority Score), RemediationTask and AuditLog.
"""

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone

from .audit import get_current_user


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMINISTRATOR = 'Administrator', 'Administrator'
        ANALYST = 'Analyst', 'Security Analyst'

    role = models.CharField(max_length=20, choices=Role.choices, default=Role.ANALYST)

    @property
    def is_administrator(self):
        return self.is_superuser or self.role == self.Role.ADMINISTRATOR

    def __str__(self):
        return self.get_full_name() or self.username


class Criticality(models.TextChoices):
    LOW = 'Low', 'Low'
    MEDIUM = 'Medium', 'Medium'
    HIGH = 'High', 'High'
    CRITICAL = 'Critical', 'Critical'


class Asset(models.Model):
    class AssetType(models.TextChoices):
        SERVER = 'Server', 'Server'
        WORKSTATION = 'Workstation', 'Workstation'
        NETWORK = 'Network Device', 'Network Device'
        APPLICATION = 'Application', 'Application'
        DATABASE = 'Database', 'Database'
        CLOUD = 'Cloud Service', 'Cloud Service'
        OTHER = 'Other', 'Other'

    class Exposure(models.TextChoices):
        INTERNAL = 'Internal', 'Internal only'
        DMZ = 'DMZ', 'DMZ / partner-facing'
        INTERNET = 'Internet', 'Internet-facing'

    name = models.CharField(max_length=150, unique=True)
    asset_type = models.CharField(max_length=30, choices=AssetType.choices, default=AssetType.SERVER)
    criticality = models.CharField(max_length=10, choices=Criticality.choices, default=Criticality.MEDIUM)
    exposure = models.CharField(max_length=10, choices=Exposure.choices, default=Exposure.INTERNAL)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    owner = models.CharField(max_length=150, blank=True, help_text='Business owner or department.')
    software_keywords = models.CharField(
        max_length=500, blank=True,
        help_text='Comma-separated product keywords or CPE fragments installed on this asset '
                  '(e.g. "apache:http_server, microsoft:windows_server_2019"). '
                  'Used to match imported CVEs to this asset.',
    )
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('asset_detail', args=[self.pk])

    @property
    def keyword_list(self):
        return [k.strip().lower() for k in self.software_keywords.split(',') if k.strip()]


class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=30, unique=True)
    description = models.TextField(blank=True)
    cvss_score = models.DecimalField(
        max_digits=3, decimal_places=1, null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(10)],
    )
    cvss_version = models.CharField(max_length=10, blank=True)
    cvss_vector = models.CharField(max_length=200, blank=True)
    severity = models.CharField(max_length=20, blank=True)
    exploit_available = models.BooleanField(
        default=False, help_text='A public exploit or proof-of-concept is referenced.')
    publicly_exploited = models.BooleanField(
        default=False, help_text='Listed in the CISA Known Exploited Vulnerabilities (KEV) catalogue.')
    patch_available = models.BooleanField(default=False, help_text='A vendor patch or advisory is referenced.')
    cpe_matches = models.TextField(blank=True, help_text='Affected product CPE strings, one per line.')
    published_date = models.DateTimeField(null=True, blank=True)
    last_modified = models.DateTimeField(null=True, blank=True)
    source = models.CharField(max_length=20, default='NVD')
    imported_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-cvss_score', 'cve_id']
        verbose_name_plural = 'vulnerabilities'

    def __str__(self):
        return self.cve_id

    def get_absolute_url(self):
        return reverse('vulnerability_detail', args=[self.pk])

    @property
    def nvd_url(self):
        return f'https://nvd.nist.gov/vuln/detail/{self.cve_id}'

    def affects(self, asset):
        """True when one of the asset's software keywords appears in this CVE's CPE list."""
        haystack = self.cpe_matches.lower()
        return any(k in haystack for k in asset.keyword_list) if haystack else False


class RiskLevel(models.TextChoices):
    LOW = 'Low', 'Low'
    MEDIUM = 'Medium', 'Medium'
    HIGH = 'High', 'High'
    CRITICAL = 'Critical', 'Critical'


class AssetVulnerability(models.Model):
    """A specific vulnerability on a specific asset; the Smart Priority Score lives here."""

    class Status(models.TextChoices):
        OPEN = 'Open', 'Open'
        ACKNOWLEDGED = 'Acknowledged', 'Acknowledged'
        IN_REMEDIATION = 'In Remediation', 'In Remediation'
        RESOLVED = 'Resolved', 'Resolved'
        RISK_ACCEPTED = 'Risk Accepted', 'Risk Accepted'
        CLOSED = 'Closed', 'Closed'

    # State chart (Chapter 3, Fig 9): allowed lifecycle transitions.
    TRANSITIONS = {
        Status.OPEN: [Status.ACKNOWLEDGED],
        Status.ACKNOWLEDGED: [Status.IN_REMEDIATION, Status.RISK_ACCEPTED],
        Status.IN_REMEDIATION: [Status.RESOLVED],
        Status.RESOLVED: [Status.CLOSED],
        Status.RISK_ACCEPTED: [Status.CLOSED],
        Status.CLOSED: [],
    }

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='asset_vulnerabilities')
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE, related_name='asset_vulnerabilities')
    priority_score = models.DecimalField(max_digits=5, decimal_places=1, default=0, db_index=True)
    risk_level = models.CharField(max_length=10, choices=RiskLevel.choices, default=RiskLevel.LOW, db_index=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN, db_index=True)
    detected_date = models.DateField(default=timezone.localdate)
    scored_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-priority_score']
        unique_together = ('asset', 'vulnerability')
        verbose_name = 'asset vulnerability'
        verbose_name_plural = 'asset vulnerabilities'

    def __str__(self):
        return f'{self.vulnerability.cve_id} on {self.asset.name}'

    def get_absolute_url(self):
        return reverse('finding_detail', args=[self.pk])

    @property
    def is_active(self):
        return self.status not in (self.Status.RESOLVED, self.Status.RISK_ACCEPTED, self.Status.CLOSED)

    def allowed_transitions(self):
        return self.TRANSITIONS.get(self.status, [])

    def can_transition_to(self, new_status):
        return new_status in self.allowed_transitions()

    def calculate_score(self, user=None):
        """Calculate and persist the Smart Priority Score (see scoring.py)."""
        from .scoring import calculate_and_save
        return calculate_and_save(self, user=user)

    def classify_risk(self):
        from .scoring import classify_risk_level
        return classify_risk_level(float(self.priority_score))


class RemediationTask(models.Model):
    class Status(models.TextChoices):
        OPEN = 'Open', 'Open'
        IN_PROGRESS = 'In Progress', 'In Progress'
        COMPLETED = 'Completed', 'Completed'
        CANCELLED = 'Cancelled', 'Cancelled'

    asset_vulnerability = models.ForeignKey(
        AssetVulnerability, on_delete=models.CASCADE, related_name='tasks')
    title = models.CharField(max_length=200)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='assigned_tasks')
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='created_tasks')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN, db_index=True)
    due_date = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['status', 'due_date']

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse('task_edit', args=[self.pk])

    @property
    def is_overdue(self):
        return (self.due_date and self.status in (self.Status.OPEN, self.Status.IN_PROGRESS)
                and self.due_date < timezone.localdate())


class AuditLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=30)
    object_type = models.CharField(max_length=50)
    object_id = models.CharField(max_length=50, blank=True)
    object_repr = models.CharField(max_length=255, blank=True)
    details = models.TextField(blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'{self.timestamp:%Y-%m-%d %H:%M} {self.user or "system"} {self.action} {self.object_repr}'

    @classmethod
    def record_action(cls, action, obj=None, details='', user=None):
        user = user or get_current_user()
        if user is not None and not getattr(user, 'is_authenticated', False):
            user = None
        return cls.objects.create(
            user=user,
            action=action,
            object_type=obj.__class__.__name__ if obj is not None else '',
            object_id=str(obj.pk) if obj is not None and obj.pk is not None else '',
            object_repr=str(obj)[:255] if obj is not None else '',
            details=details,
        )
