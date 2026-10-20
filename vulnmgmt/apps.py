from django.apps import AppConfig


class VulnmgmtConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vulnmgmt'
    verbose_name = 'Vulnerability Management'

    def ready(self):
        from . import signals  # noqa: F401
