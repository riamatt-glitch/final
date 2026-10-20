from django import forms
from django.contrib.auth import get_user_model

from .models import Asset, AssetVulnerability, RemediationTask, Vulnerability


class BootstrapMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs.setdefault('class', 'form-check-input')
            elif isinstance(widget, forms.Select):
                widget.attrs.setdefault('class', 'form-select')
            else:
                widget.attrs.setdefault('class', 'form-control')


class AssetForm(BootstrapMixin, forms.ModelForm):
    class Meta:
        model = Asset
        fields = ['name', 'asset_type', 'criticality', 'exposure', 'ip_address', 'owner',
                  'software_keywords', 'description']
        widgets = {'description': forms.Textarea(attrs={'rows': 3}),
                   'software_keywords': forms.TextInput()}


class VulnerabilityForm(BootstrapMixin, forms.ModelForm):
    """Manual entry or correction of a vulnerability record."""

    class Meta:
        model = Vulnerability
        fields = ['cve_id', 'description', 'cvss_score', 'severity', 'exploit_available',
                  'publicly_exploited', 'patch_available', 'cpe_matches']
        widgets = {'description': forms.Textarea(attrs={'rows': 3}),
                   'cpe_matches': forms.Textarea(attrs={'rows': 3})}

    def clean_cve_id(self):
        return self.cleaned_data['cve_id'].strip().upper()


class NVDImportForm(BootstrapMixin, forms.Form):
    cve_id = forms.CharField(label='CVE ID', required=False, help_text='e.g. CVE-2021-44228')
    keyword = forms.CharField(required=False, help_text='e.g. "apache http server" or "fortinet"')
    days = forms.IntegerField(label='Published in the last N days', required=False, min_value=1,
                              max_value=120)
    kev_only = forms.BooleanField(label='Only CISA Known Exploited Vulnerabilities', required=False)
    max_results = forms.IntegerField(initial=50, min_value=1, max_value=2000)

    def clean(self):
        data = super().clean()
        if not (data.get('cve_id') or data.get('keyword') or data.get('days') or data.get('kev_only')):
            raise forms.ValidationError('Enter a CVE ID, a keyword, a date range or choose KEV only.')
        return data


class FindingForm(BootstrapMixin, forms.ModelForm):
    """Manually link a vulnerability to an asset."""

    class Meta:
        model = AssetVulnerability
        fields = ['asset', 'vulnerability', 'detected_date', 'notes']
        widgets = {'detected_date': forms.DateInput(attrs={'type': 'date'}),
                   'notes': forms.Textarea(attrs={'rows': 2})}


class TransitionForm(BootstrapMixin, forms.Form):
    status = forms.ChoiceField(choices=())
    note = forms.CharField(required=False, widget=forms.Textarea(attrs={'rows': 2}))

    def __init__(self, finding, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['status'].choices = [(s, s) for s in finding.allowed_transitions()]


class TaskForm(BootstrapMixin, forms.ModelForm):
    class Meta:
        model = RemediationTask
        fields = ['title', 'assigned_to', 'status', 'due_date', 'notes']
        widgets = {'due_date': forms.DateInput(attrs={'type': 'date'}, format='%Y-%m-%d'),
                   'notes': forms.Textarea(attrs={'rows': 3})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['assigned_to'].queryset = get_user_model().objects.filter(is_active=True).order_by('username')


class TaskStatusForm(BootstrapMixin, forms.ModelForm):
    """What an analyst may change on a task assigned to them."""

    class Meta:
        model = RemediationTask
        fields = ['status', 'notes']
        widgets = {'notes': forms.Textarea(attrs={'rows': 3})}
