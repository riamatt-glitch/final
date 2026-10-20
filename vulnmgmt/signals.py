"""Audit logging and automatic re-scoring driven by model signals."""

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver

from .models import Asset, AssetVulnerability, AuditLog, RemediationTask, Vulnerability

AUDITED_MODELS = (Asset, Vulnerability, AssetVulnerability, RemediationTask)
SCORE_INPUT_FIELDS = {
    Asset: ('criticality', 'exposure'),
    Vulnerability: ('cvss_score', 'exploit_available', 'publicly_exploited', 'patch_available'),
}


def _changes(instance):
    old = getattr(instance, '_original', None)
    if not old:
        return {}
    return {name: (old[name], getattr(instance, name)) for name in old
            if old[name] != getattr(instance, name)}


@receiver(pre_save)
def remember_original(sender, instance, **kwargs):
    if sender not in AUDITED_MODELS or not instance.pk:
        return
    original = sender.objects.filter(pk=instance.pk).values().first()
    if original:
        instance._original = {f.attname: original.get(f.attname) for f in sender._meta.concrete_fields
                              if f.attname not in ('updated_at', 'imported_at', 'scored_at')}


@receiver(post_save)
def audit_save(sender, instance, created, **kwargs):
    if sender not in AUDITED_MODELS:
        return
    changes = _changes(instance)
    if not getattr(instance, '_skip_audit', False):
        if created:
            AuditLog.record_action('CREATE', instance)
        elif changes:
            details = '; '.join(f'{k}: {a} -> {b}' for k, (a, b) in changes.items())
            AuditLog.record_action('UPDATE', instance, details)
    instance._skip_audit = False

    # Changing a score input re-scores every finding that depends on it.
    if not created and any(f in changes for f in SCORE_INPUT_FIELDS.get(sender, ())):
        from .scoring import rescore_queryset
        rescore_queryset(instance.asset_vulnerabilities.all())
    instance._original = None


@receiver(post_delete)
def audit_delete(sender, instance, **kwargs):
    if sender in AUDITED_MODELS:
        AuditLog.record_action('DELETE', instance)


@receiver(user_logged_in)
def audit_login(sender, request, user, **kwargs):
    AuditLog.record_action('LOGIN', user, user=user)


@receiver(user_logged_out)
def audit_logout(sender, request, user, **kwargs):
    if user is not None:
        AuditLog.record_action('LOGOUT', user, user=user)


@receiver(user_login_failed)
def audit_login_failed(sender, credentials, request=None, **kwargs):
    AuditLog.record_action('LOGIN_FAILED', None, f"username={credentials.get('username', '')}")
