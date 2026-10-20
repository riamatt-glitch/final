from django.urls import path

from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),

    path('findings/', views.finding_list, name='finding_list'),
    path('findings/new/', views.finding_create, name='finding_create'),
    path('findings/rescore/', views.rescore_all, name='rescore_all'),
    path('findings/<int:pk>/', views.finding_detail, name='finding_detail'),
    path('findings/<int:pk>/transition/', views.finding_transition, name='finding_transition'),
    path('findings/<int:pk>/rescore/', views.finding_rescore, name='finding_rescore'),
    path('findings/<int:finding_pk>/tasks/new/', views.task_create, name='task_create'),

    path('assets/', views.asset_list, name='asset_list'),
    path('assets/new/', views.asset_edit, name='asset_create'),
    path('assets/<int:pk>/', views.asset_detail, name='asset_detail'),
    path('assets/<int:pk>/edit/', views.asset_edit, name='asset_edit'),
    path('assets/<int:pk>/delete/', views.asset_delete, name='asset_delete'),

    path('vulnerabilities/', views.vulnerability_list, name='vulnerability_list'),
    path('vulnerabilities/new/', views.vulnerability_edit, name='vulnerability_create'),
    path('vulnerabilities/import/', views.nvd_import, name='nvd_import'),
    path('vulnerabilities/<int:pk>/', views.vulnerability_detail, name='vulnerability_detail'),
    path('vulnerabilities/<int:pk>/edit/', views.vulnerability_edit, name='vulnerability_edit'),

    path('tasks/', views.task_list, name='task_list'),
    path('tasks/<int:pk>/', views.task_edit, name='task_edit'),

    path('reports/', views.reports, name='reports'),
    path('reports/findings.csv', views.export_findings_csv, name='export_findings_csv'),
    path('reports/comparison/', views.comparison, name='comparison'),
    path('audit/', views.audit_log, name='audit_log'),
    path('scoring/', views.about_scoring, name='about_scoring'),
]
