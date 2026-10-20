from django import template
from django.utils.html import format_html

register = template.Library()

RISK_CLASSES = {'Critical': 'risk-critical', 'High': 'risk-high', 'Medium': 'risk-medium', 'Low': 'risk-low'}
STATUS_CLASSES = {
    'Open': 'text-bg-danger', 'Acknowledged': 'text-bg-warning', 'In Remediation': 'text-bg-primary',
    'In Progress': 'text-bg-primary', 'Resolved': 'text-bg-success', 'Completed': 'text-bg-success',
    'Risk Accepted': 'text-bg-secondary', 'Cancelled': 'text-bg-secondary', 'Closed': 'text-bg-dark',
}


@register.simple_tag
def risk_badge(level):
    return format_html('<span class="badge {}">{}</span>', RISK_CLASSES.get(level, 'text-bg-light'), level or '-')


@register.simple_tag
def status_badge(status):
    return format_html('<span class="badge {}">{}</span>', STATUS_CLASSES.get(status, 'text-bg-light'), status)


def cvss_level(score):
    s = float(score)
    return 'Critical' if s >= 9 else 'High' if s >= 7 else 'Medium' if s >= 4 else 'Low'


@register.simple_tag
def cvss_badge(score):
    if score is None:
        return format_html('<span class="text-muted">n/a</span>')
    return format_html('<span class="badge {}">{}</span>', RISK_CLASSES[cvss_level(score)], score)


@register.simple_tag
def yesno_icon(value):
    return format_html('<span class="{}">{}</span>', 'text-danger fw-semibold' if value else 'text-muted',
                       'Yes' if value else 'No')


@register.filter
def percent_of(value, total):
    try:
        return round(100 * float(value) / float(total), 1)
    except (TypeError, ValueError, ZeroDivisionError):
        return 0
