import csv
import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db.models import Avg, Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from .forms import (AssetForm, FindingForm, NVDImportForm, TaskForm, TaskStatusForm, TransitionForm,
                    VulnerabilityForm)
from .models import Asset, AssetVulnerability, AuditLog, RemediationTask, RiskLevel, Vulnerability
from .nvd import NVDError
from .permissions import admin_required
from .scoring import breakdown_for, get_weights, rescore_queryset
from .services import import_from_nvd, match_asset, match_vulnerability
from .templatetags.rbvms_tags import RISK_CLASSES, STATUS_CLASSES, cvss_level

RISK_ORDER = ['Critical', 'High', 'Medium', 'Low']
ACTIVE_STATUSES = ['Open', 'Acknowledged', 'In Remediation']


def factor_label(name):
    """'publicly_exploited' -> 'Publicly exploited'; acronyms stay upper case."""
    return 'CVSS' if name == 'cvss' else name.replace('_', ' ').capitalize()


def _active_findings():
    return AssetVulnerability.objects.filter(status__in=ACTIVE_STATUSES)


# ---------------------------------------------------------------- dashboard

@login_required
def dashboard(request):
    active = _active_findings()
    by_risk = dict(active.values_list('risk_level').annotate(n=Count('id')))
    by_status = dict(AssetVulnerability.objects.values_list('status').annotate(n=Count('id')))
    open_tasks = RemediationTask.objects.filter(status__in=['Open', 'In Progress'])
    context = {
        'total_assets': Asset.objects.count(),
        'total_vulns': Vulnerability.objects.count(),
        'active_findings': active.count(),
        'critical_findings': by_risk.get('Critical', 0),
        'open_tasks': open_tasks.count(),
        'overdue_tasks': open_tasks.filter(due_date__lt=timezone.localdate()).count(),
        'top_findings': active.select_related('asset', 'vulnerability')[:10],
        'my_tasks': open_tasks.filter(assigned_to=request.user).select_related(
            'asset_vulnerability__asset', 'asset_vulnerability__vulnerability')[:5],
        'risk_chart': json.dumps({'labels': RISK_ORDER, 'data': [by_risk.get(r, 0) for r in RISK_ORDER]}),
        'status_chart': json.dumps({'labels': list(AssetVulnerability.Status.values),
                                    'data': [by_status.get(s, 0) for s in AssetVulnerability.Status.values]}),
        'asset_chart': json.dumps(_asset_risk_chart()),
        'recent_activity': AuditLog.objects.select_related('user')[:8],
    }
    return render(request, 'vulnmgmt/dashboard.html', context)


def _asset_risk_chart():
    rows = (_active_findings().values('asset__name')
            .annotate(total=Count('id'), avg=Avg('priority_score'))
            .order_by('-avg')[:8])
    return {'labels': [r['asset__name'] for r in rows],
            'avg': [round(float(r['avg'] or 0), 1) for r in rows],
            'total': [r['total'] for r in rows]}


# ---------------------------------------------------------------- findings (prioritised list)

FINDING_ROW_FIELDS = (
    'pk', 'priority_score', 'risk_level', 'status', 'detected_date', 'asset_id', 'asset__name',
    'asset__criticality', 'asset__exposure', 'vulnerability__cve_id', 'vulnerability__cvss_score',
    'vulnerability__exploit_available', 'vulnerability__publicly_exploited', 'vulnerability__patch_available',
)


def _finding_rows(page):
    """Flatten a page of findings into plain dicts so the list of up to 5,000 rows renders quickly (NFR 1)."""
    finding_url = reverse('finding_detail', args=[0])[:-2]
    asset_url = reverse('asset_detail', args=[0])[:-2]
    rows = []
    for rank, f in enumerate(page.object_list, start=page.start_index()):
        cvss = f['vulnerability__cvss_score']
        rows.append({
            'rank': rank, 'score': f['priority_score'], 'risk': f['risk_level'],
            'risk_class': RISK_CLASSES.get(f['risk_level'], ''),
            'status': f['status'], 'status_class': STATUS_CLASSES.get(f['status'], ''),
            'url': f'{finding_url}{f["pk"]}/', 'asset_url': f'{asset_url}{f["asset_id"]}/',
            'cve': f['vulnerability__cve_id'], 'asset': f['asset__name'],
            'criticality': f['asset__criticality'], 'exposure': f['asset__exposure'],
            'cvss': cvss, 'cvss_class': RISK_CLASSES[cvss_level(cvss)] if cvss is not None else '',
            'exploit': f['vulnerability__exploit_available'], 'kev': f['vulnerability__publicly_exploited'],
            'patch': f['vulnerability__patch_available'], 'detected': f['detected_date'],
        })
    return rows


@login_required
def finding_list(request):
    qs = AssetVulnerability.objects.select_related('asset', 'vulnerability')
    q = request.GET.get('q', '').strip()
    risk = request.GET.get('risk', '')
    status = request.GET.get('status', 'active')
    asset_id = request.GET.get('asset', '')
    if q:
        qs = qs.filter(Q(vulnerability__cve_id__icontains=q) | Q(asset__name__icontains=q)
                       | Q(vulnerability__description__icontains=q))
    if risk in RISK_ORDER:
        qs = qs.filter(risk_level=risk)
    if status == 'active':
        qs = qs.filter(status__in=ACTIVE_STATUSES)
    elif status in AssetVulnerability.Status.values:
        qs = qs.filter(status=status)
    if asset_id.isdigit():
        qs = qs.filter(asset_id=asset_id)
    qs = qs.order_by('-priority_score', '-vulnerability__cvss_score', 'id')

    try:
        per_page = min(max(int(request.GET.get('per_page', 50)), 10), 5000)
    except ValueError:
        per_page = 50
    page = Paginator(qs.values(*FINDING_ROW_FIELDS), per_page).get_page(request.GET.get('page'))
    params = request.GET.copy()
    params.pop('page', None)
    return render(request, 'vulnmgmt/finding_list.html', {
        'page': page, 'rows': _finding_rows(page), 'q': q, 'risk': risk, 'status': status, 'asset_id': asset_id,
        'per_page': per_page, 'querystring': params.urlencode(),
        'risk_levels': RISK_ORDER, 'statuses': AssetVulnerability.Status.values,
        'assets': Asset.objects.only('id', 'name'),
    })


@login_required
def finding_detail(request, pk):
    finding = get_object_or_404(AssetVulnerability.objects.select_related('asset', 'vulnerability'), pk=pk)
    breakdown = breakdown_for(finding)
    weights = get_weights()
    factors = [{'name': factor_label(name), 'value': round(value, 2), 'pct': round(value * 100),
                'weight': weights[name], 'points': breakdown.contributions[name]}
               for name, value in breakdown.factors.items()]
    return render(request, 'vulnmgmt/finding_detail.html', {
        'finding': finding,
        'factors': factors,
        'breakdown': breakdown,
        'transition_form': TransitionForm(finding) if finding.allowed_transitions() else None,
        'tasks': finding.tasks.select_related('assigned_to'),
        'history': AuditLog.objects.filter(object_type='AssetVulnerability', object_id=str(finding.pk))[:20],
    })


@admin_required
@require_POST
def finding_transition(request, pk):
    finding = get_object_or_404(AssetVulnerability, pk=pk)
    form = TransitionForm(finding, request.POST)
    if form.is_valid() and finding.can_transition_to(form.cleaned_data['status']):
        old = finding.status
        finding.status = form.cleaned_data['status']
        note = form.cleaned_data['note']
        if note:
            stamp = timezone.localtime().strftime('%Y-%m-%d %H:%M')
            finding.notes = f'{finding.notes}\n[{stamp} {request.user}] {old} -> {finding.status}: {note}'.strip()
        finding.save()
        if finding.status in ('Resolved', 'Risk Accepted', 'Closed'):
            finding.tasks.filter(status__in=['Open', 'In Progress']).update(
                status='Completed' if finding.status == 'Resolved' else 'Cancelled',
                completed_at=timezone.now())
        finding.calculate_score(user=request.user)
        messages.success(request, f'Status changed from {old} to {finding.status}.')
    else:
        messages.error(request, 'That status change is not allowed from the current state.')
    return redirect(finding)


@admin_required
@require_POST
def finding_rescore(request, pk):
    finding = get_object_or_404(AssetVulnerability, pk=pk)
    result = finding.calculate_score(user=request.user)
    messages.success(request, f'Smart Priority Score recalculated: {result.score} ({result.risk_level}).')
    return redirect(finding)


@admin_required
def finding_create(request):
    form = FindingForm(request.POST or None, initial={
        'asset': request.GET.get('asset'), 'vulnerability': request.GET.get('vulnerability')})
    if request.method == 'POST' and form.is_valid():
        try:
            finding = form.save()
        except IntegrityError:
            form.add_error(None, 'That vulnerability is already recorded against this asset.')
        else:
            rescore_queryset(finding.vulnerability.asset_vulnerabilities.all(), user=request.user)
            messages.success(request, 'Finding recorded and scored.')
            return redirect(finding)
    return render(request, 'vulnmgmt/form.html', {'form': form, 'title': 'Link vulnerability to asset'})


@admin_required
@require_POST
def rescore_all(request):
    count = rescore_queryset(AssetVulnerability.objects.all(), user=request.user)
    messages.success(request, f'Recalculated the Smart Priority Score for {count} findings.')
    return redirect(request.POST.get('next') or 'finding_list')


# ---------------------------------------------------------------- assets

@login_required
def asset_list(request):
    assets = Asset.objects.annotate(
        active=Count('asset_vulnerabilities', filter=Q(asset_vulnerabilities__status__in=ACTIVE_STATUSES)),
        critical=Count('asset_vulnerabilities', filter=Q(asset_vulnerabilities__status__in=ACTIVE_STATUSES,
                                                         asset_vulnerabilities__risk_level='Critical')),
        avg_score=Avg('asset_vulnerabilities__priority_score',
                      filter=Q(asset_vulnerabilities__status__in=ACTIVE_STATUSES)),
    )
    return render(request, 'vulnmgmt/asset_list.html', {'assets': assets})


@login_required
def asset_detail(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    findings = asset.asset_vulnerabilities.select_related('vulnerability')
    return render(request, 'vulnmgmt/asset_detail.html', {'asset': asset, 'findings': findings})


@admin_required
def asset_edit(request, pk=None):
    asset = get_object_or_404(Asset, pk=pk) if pk else None
    form = AssetForm(request.POST or None, instance=asset)
    if request.method == 'POST' and form.is_valid():
        asset = form.save()
        new = match_asset(asset, user=request.user)
        msg = f'Asset "{asset}" saved.'
        if new:
            msg += f' {len(new)} matching vulnerabilities were linked and scored.'
        messages.success(request, msg)
        return redirect(asset)
    return render(request, 'vulnmgmt/form.html', {
        'form': form, 'title': f'Edit {asset}' if asset else 'Add asset', 'cancel': asset or None})


@admin_required
def asset_delete(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    if request.method == 'POST':
        asset.delete()
        messages.success(request, f'Asset "{asset}" deleted.')
        return redirect('asset_list')
    return render(request, 'vulnmgmt/confirm_delete.html', {'object': asset, 'cancel': asset})


# ---------------------------------------------------------------- vulnerabilities

@login_required
def vulnerability_list(request):
    qs = Vulnerability.objects.annotate(asset_count=Count('asset_vulnerabilities')).order_by('-cvss_score', 'cve_id')
    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(Q(cve_id__icontains=q) | Q(description__icontains=q))
    if request.GET.get('kev'):
        qs = qs.filter(publicly_exploited=True)
    page = Paginator(qs, 50).get_page(request.GET.get('page'))
    params = request.GET.copy()
    params.pop('page', None)
    return render(request, 'vulnmgmt/vulnerability_list.html',
                  {'page': page, 'q': q, 'kev': request.GET.get('kev', ''), 'querystring': params.urlencode()})


@login_required
def vulnerability_detail(request, pk):
    vuln = get_object_or_404(Vulnerability, pk=pk)
    findings = vuln.asset_vulnerabilities.select_related('asset')
    return render(request, 'vulnmgmt/vulnerability_detail.html', {
        'vuln': vuln, 'findings': findings, 'cpes': [c for c in vuln.cpe_matches.splitlines() if c]})


@admin_required
def vulnerability_edit(request, pk=None):
    vuln = get_object_or_404(Vulnerability, pk=pk) if pk else None
    form = VulnerabilityForm(request.POST or None, instance=vuln)
    if request.method == 'POST' and form.is_valid():
        vuln = form.save(commit=False)
        if not pk:
            vuln.source = 'Manual'
        vuln.save()
        new = match_vulnerability(vuln, user=request.user)
        messages.success(request, f'{vuln} saved' + (f'; linked to {len(new)} assets.' if new else '.'))
        return redirect(vuln)
    return render(request, 'vulnmgmt/form.html', {
        'form': form, 'title': f'Edit {vuln}' if vuln else 'Add vulnerability manually', 'cancel': vuln})


@admin_required
def nvd_import(request):
    form = NVDImportForm(request.POST or None)
    result = None
    if request.method == 'POST' and form.is_valid():
        d = form.cleaned_data
        try:
            result = import_from_nvd(keyword=d['keyword'] or None, cve_id=d['cve_id'] or None,
                                     days=d['days'], max_results=d['max_results'],
                                     kev_only=d['kev_only'], user=request.user)
        except NVDError as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, f'Imported {result.created} new and updated {result.updated} CVE records; '
                                      f'{result.findings_created} new asset findings were created and scored.')
    return render(request, 'vulnmgmt/nvd_import.html', {'form': form, 'result': result})


# ---------------------------------------------------------------- remediation tasks

@login_required
def task_list(request):
    qs = RemediationTask.objects.select_related(
        'assigned_to', 'asset_vulnerability__asset', 'asset_vulnerability__vulnerability')
    scope = request.GET.get('scope', 'mine' if not request.user.is_administrator else 'open')
    if scope == 'mine':
        qs = qs.filter(assigned_to=request.user)
    if scope in ('mine', 'open'):
        qs = qs.filter(status__in=['Open', 'In Progress'])
    elif scope == 'overdue':
        qs = qs.filter(status__in=['Open', 'In Progress'], due_date__lt=timezone.localdate())
    qs = qs.order_by('due_date', '-asset_vulnerability__priority_score')
    page = Paginator(qs, 50).get_page(request.GET.get('page'))
    return render(request, 'vulnmgmt/task_list.html', {'page': page, 'scope': scope})


@admin_required
def task_create(request, finding_pk):
    finding = get_object_or_404(AssetVulnerability, pk=finding_pk)
    task = RemediationTask(asset_vulnerability=finding, created_by=request.user,
                           title=f'Remediate {finding.vulnerability.cve_id} on {finding.asset.name}')
    return _task_form(request, task, TaskForm, f'New remediation task for {finding}')


@login_required
def task_edit(request, pk):
    task = get_object_or_404(RemediationTask.objects.select_related('asset_vulnerability'), pk=pk)
    if request.user.is_administrator:
        form_class = TaskForm
    elif task.assigned_to_id == request.user.id:
        form_class = TaskStatusForm
    else:
        raise PermissionDenied('You can only update remediation tasks assigned to you.')
    return _task_form(request, task, form_class, f'Remediation task: {task.title}')


def _task_form(request, task, form_class, title):
    form = form_class(request.POST or None, instance=task)
    if request.method == 'POST' and form.is_valid():
        task = form.save(commit=False)
        if task.status in ('Completed', 'Cancelled') and not task.completed_at:
            task.completed_at = timezone.now()
        task.save()
        finding = task.asset_vulnerability
        # State chart: assigning remediation moves an acknowledged finding to "In Remediation".
        if task.assigned_to_id and task.status in ('Open', 'In Progress') and finding.status in ('Open', 'Acknowledged'):
            finding.status = 'In Remediation'
            finding.save()
            finding.calculate_score(user=request.user)
        messages.success(request, 'Remediation task saved.')
        return redirect(finding)
    return render(request, 'vulnmgmt/form.html', {'form': form, 'title': title, 'cancel': task.asset_vulnerability})


# ---------------------------------------------------------------- reports & evaluation

@login_required
def reports(request):
    findings = AssetVulnerability.objects.all()
    risk_status = []
    for level in RISK_ORDER:
        row = {'level': level, 'cells': [findings.filter(risk_level=level, status=s).count()
                                          for s in AssetVulnerability.Status.values]}
        row['total'] = sum(row['cells'])
        risk_status.append(row)
    tasks = RemediationTask.objects.all()
    total_tasks = tasks.count()
    completed = tasks.filter(status='Completed').count()
    by_assignee = (tasks.values('assigned_to__username')
                   .annotate(total=Count('id'),
                             done=Count('id', filter=Q(status='Completed')),
                             overdue=Count('id', filter=Q(status__in=['Open', 'In Progress'],
                                                          due_date__lt=timezone.localdate())))
                   .order_by('assigned_to__username'))
    return render(request, 'vulnmgmt/reports.html', {
        'statuses': AssetVulnerability.Status.values,
        'risk_status': risk_status,
        'total_findings': findings.count(),
        'total_tasks': total_tasks,
        'completed_tasks': completed,
        'completion_rate': round(100 * completed / total_tasks, 1) if total_tasks else 0,
        'by_assignee': by_assignee,
        'by_asset': (findings.filter(status__in=ACTIVE_STATUSES).values('asset__name', 'asset__criticality')
                     .annotate(total=Count('id'), critical=Count('id', filter=Q(risk_level='Critical')),
                               high=Count('id', filter=Q(risk_level='High')), avg=Avg('priority_score'))
                     .order_by('-avg')),
    })


@login_required
def export_findings_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="findings-{timezone.localdate()}.csv"'
    writer = csv.writer(response)
    writer.writerow(['CVE', 'Asset', 'Asset criticality', 'Exposure', 'CVSS', 'Exploit available',
                     'Known exploited (KEV)', 'Patch available', 'Smart Priority Score', 'Risk level',
                     'Status', 'Detected'])
    for f in AssetVulnerability.objects.select_related('asset', 'vulnerability').order_by('-priority_score'):
        v = f.vulnerability
        writer.writerow([v.cve_id, f.asset.name, f.asset.criticality, f.asset.exposure, v.cvss_score,
                         v.exploit_available, v.publicly_exploited, v.patch_available,
                         f.priority_score, f.risk_level, f.status, f.detected_date])
    AuditLog.record_action('EXPORT', None, 'Findings CSV export', user=request.user)
    return response


@login_required
def comparison(request):
    """Evaluation view (Section 2.2): Smart Priority ranking vs. a naive CVSS-only ranking."""
    findings = list(_active_findings().select_related('asset', 'vulnerability'))
    cvss_sorted = sorted(findings, key=lambda f: (-(float(f.vulnerability.cvss_score or 0)), f.pk))
    cvss_rank = {f.pk: i + 1 for i, f in enumerate(cvss_sorted)}
    smart_sorted = sorted(findings, key=lambda f: (-float(f.priority_score), f.pk))
    rows = []
    for i, f in enumerate(smart_sorted, start=1):
        rows.append({'finding': f, 'smart_rank': i, 'cvss_rank': cvss_rank[f.pk],
                     'shift': cvss_rank[f.pk] - i})
    try:
        top_n = max(int(request.GET.get('top', 10)), 1)
    except ValueError:
        top_n = 10
    smart_top = {f.pk for f in smart_sorted[:top_n]}
    cvss_top = {f.pk for f in cvss_sorted[:top_n]}
    return render(request, 'vulnmgmt/comparison.html', {
        'rows': rows[:200], 'top_n': top_n, 'total': len(findings),
        'overlap': len(smart_top & cvss_top),
        'promoted': [f for f in smart_sorted[:top_n] if f.pk not in cvss_top],
        'demoted': [f for f in cvss_sorted[:top_n] if f.pk not in smart_top],
    })


@admin_required
def audit_log(request):
    qs = AuditLog.objects.select_related('user')
    action = request.GET.get('action', '')
    if action:
        qs = qs.filter(action=action)
    page = Paginator(qs, 100).get_page(request.GET.get('page'))
    return render(request, 'vulnmgmt/audit_log.html', {
        'page': page, 'action': action,
        'actions': AuditLog.objects.values_list('action', flat=True).distinct().order_by('action')})


@login_required
def about_scoring(request):
    weights = get_weights()
    from .scoring import CRITICALITY_FACTOR, EXPOSURE_FACTOR, REMEDIATION_FACTOR, REMEDIATION_SLA_DAYS, RISK_THRESHOLDS
    return render(request, 'vulnmgmt/about_scoring.html', {
        'weights': {factor_label(k): v for k, v in weights.items()}, 'criticality': CRITICALITY_FACTOR, 'exposure': EXPOSURE_FACTOR,
        'remediation': REMEDIATION_FACTOR, 'thresholds': RISK_THRESHOLDS, 'sla': REMEDIATION_SLA_DAYS,
        'risk_levels': RiskLevel.values,
    })
