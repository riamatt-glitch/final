# Evidence that the aims and objectives are met

Screenshots of the working Risk-Based Vulnerability Assessment and Management System (RBVMS),
captured on 21 October 2026 from the running application (Django 5 on MySQL 8.0.45). All CVE data is real data imported
live from the NVD API 2.0. Assets, users and remediation activity are fabricated, as stated in Section 1.8.

Captions are written so they can be used as figure captions in the report.

---

## Aim

> To design and develop a Risk-Based Vulnerability Assessment and Management System that enables organizations to identify,
> assess, prioritize, and manage cybersecurity vulnerabilities by combining technical vulnerability data with organizational risk factors.

| Part of the aim | Evidence |
|---|---|
| **Identify** vulnerabilities | 04, 05, 06: CVEs imported live from the NVD and matched to the assets they affect |
| **Assess** them | 07, 08: each finding is assessed with the Smart Priority Score |
| **Prioritize** them | 02, 03, 15: findings are ranked by organisational risk, not by CVSS alone |
| **Manage** them | 12, 13, 14, 17: remediation tasks, the lifecycle, reports and the audit trail |
| **Combining technical data with organisational risk factors** | 05, 08: CVSS and exploit data from the NVD combined with asset criticality and exposure |

---

## Objective 1: Study existing approaches based on CVE and CVSS

The study itself is the literature review in Chapter 2. These screenshots show the system built on those two standards.

| Screenshot | Caption |
|---|---|
| `04_vulnerability_records_from_nvd.png` | Vulnerability records imported from the NVD, identified by CVE ID, with their CVSS base score, severity, exploit, CISA KEV and patch status. |
| `05_cve_detail_log4shell_cvss_and_affected_assets.png` | CVE-2021-44228 (Log4Shell): the NVD description, CVSS v3.1 base score 10.0 with its full vector string, affected products (CPE), and the three organisational assets it affects. |
| `06_live_nvd_import_result.png` | A live import of CVE-2021-45105 through the NVD CVE API 2.0. One new record was created and automatically matched and scored against three assets. |

## Objective 2: Identify the key factors that influence prioritization

| Screenshot | Caption |
|---|---|
| `07_scoring_model_factors_and_weights.png` | The prioritization factors used: CVSS, asset criticality, exploit availability, active exploitation (CISA KEV), exposure, number of affected systems, patch availability and remediation status. Shows how each factor is valued and how the score maps to risk levels. |
| `08_score_breakdown_zerologon_finance_db_server.png` | The factors applied to one finding, showing how much each one contributes to the score. |
| `09_asset_inventory_criticality.png` | The asset inventory, recording each asset's business criticality and exposure, the organisational factors that CVSS does not capture. |
| `10_asset_detail_finance_db_server.png` | One asset with its criticality, exposure and every vulnerability recorded against it. |

## Objective 3: Design a normalized relational SQL database

| Screenshot | Caption |
|---|---|
| `11_database_schema_mysql.png` | The relational schema read directly from MySQL 8.0.45 (`information_schema`): six project tables (User, Asset, Vulnerability, AssetVulnerability, RemediationTask, AuditLog), their primary keys, six foreign keys enforcing referential integrity, and unique constraints. The many-to-many relationship between assets and vulnerabilities is resolved through the AssetVulnerability association table, matching the class diagram in Chapter 3. |

## Objective 4: Calculate a custom organizational risk score using predefined weights

| Screenshot | Caption |
|---|---|
| `07_scoring_model_factors_and_weights.png` | The predefined weighting criteria. The weights sum to 100, so the Smart Priority Score ranges from 0 to 100. |
| `08_score_breakdown_zerologon_finance_db_server.png` | CVE-2020-1472 (Zerologon) has an NVD CVSS score of only 5.5. On the critical Finance DB Server, where it is known to be actively exploited, the Smart Priority Score is 71.5 (High). The breakdown shows the points each weighted factor contributes. |
| `05_cve_detail_log4shell_cvss_and_affected_assets.png` | The same CVE (CVSS 10.0) receives a different score on each asset: 86.8 on the internet-facing Customer Web Portal, 79.8 on the internal Claims Processing App and 64.8 on the low-criticality Dev/Test VM. |

## Objective 5: Implement a dashboard that helps administrators prioritize remediation

| Screenshot | Caption |
|---|---|
| `02_dashboard.png` | The vulnerability risk dashboard: summary counts, active findings by risk level, the remediation lifecycle, the riskiest assets, and the ten highest-priority vulnerabilities ordered by Smart Priority Score. |
| `03_prioritised_findings.png` | The full prioritized list of findings with filters, ranked by Smart Priority Score. |
| `12_remediation_tasks.png` | Remediation tasks generated for Medium, High and Critical findings, with assignees, due dates and overdue items highlighted. |
| `13_finding_lifecycle_and_history.png` | A finding in remediation: its lifecycle status (following the Chapter 3 state chart), its assigned task, and its history. |
| `14_reports_status_and_progress.png` | Management report: findings by risk level and lifecycle status, active risk by asset, and remediation workload and completion rate. |

## Objective 6: Test and evaluate the system's effectiveness

| Screenshot | Caption |
|---|---|
| `16_automated_test_results.png` | All 61 automated tests pass against MySQL. They cover the score calculation and its pre- and post-conditions (Section 3.7), repeatability of the score (NFR 3), password hashing (NFR 2), a 5,000-record list rendering in under 5 seconds (NFR 1), NVD parsing and retries, the state-chart transitions and role-based access. |
| `15_evaluation_smart_vs_cvss_ranking.png` | Evaluation (Section 2.2): the same 32 active findings ranked by Smart Priority Score and by CVSS alone. Only 5 of the top 10 agree. Zerologon on the Finance DB Server rises 19 places (CVSS rank 31 to Smart rank 12), and Log4Shell on the low-value Dev/Test VM falls 17 places (rank 3 to rank 20). Organizational context changes remediation priorities. |
| `17_audit_log.png` | The audit log recording logins, imports, score calculations and every change, with user and time. |
| `18_access_denied_for_analyst.png` | Role-based access control: a Security Analyst is refused an Administrator-only page. |

## Supporting

| Screenshot | Caption |
|---|---|
| `01_login_page.png` | Secure sign-in. Every page requires authentication (FR1). |
