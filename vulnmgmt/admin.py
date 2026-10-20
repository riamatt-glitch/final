from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import Asset, AssetVulnerability, AuditLog, RemediationTask, User, Vulnerability
from .scoring import rescore_queryset


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'is_active', 'last_login')
    list_filter = ('role', 'is_active', 'is_superuser')
    fieldsets = BaseUserAdmin.fieldsets + (('RBVMS', {'fields': ('role',)}),)
    add_fieldsets = BaseUserAdmin.add_fieldsets + (('RBVMS', {'fields': ('role',)}),)


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('name', 'asset_type', 'criticality', 'exposure', 'owner')
    list_filter = ('asset_type', 'criticality', 'exposure')
    search_fields = ('name', 'owner', 'software_keywords')


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'cvss_score', 'severity', 'exploit_available', 'publicly_exploited',
                    'patch_available', 'published_date', 'source')
    list_filter = ('severity', 'exploit_available', 'publicly_exploited', 'patch_available', 'source')
    search_fields = ('cve_id', 'description')


@admin.action(description='Recalculate Smart Priority Score')
def recalculate(modeladmin, request, queryset):
    count = rescore_queryset(queryset, user=request.user)
    modeladmin.message_user(request, f'Recalculated {count} findings.')


@admin.register(AssetVulnerability)
class AssetVulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('vulnerability', 'asset', 'priority_score', 'risk_level', 'status', 'detected_date')
    list_filter = ('risk_level', 'status')
    search_fields = ('vulnerability__cve_id', 'asset__name')
    readonly_fields = ('priority_score', 'risk_level', 'scored_at')
    actions = [recalculate]


@admin.register(RemediationTask)
class RemediationTaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'assigned_to', 'status', 'due_date')
    list_filter = ('status',)
    search_fields = ('title',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'action', 'object_type', 'object_repr')
    list_filter = ('action', 'object_type')
    search_fields = ('object_repr', 'details')

    # The audit trail is append-only.
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
