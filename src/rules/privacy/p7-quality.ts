/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const p7Rules: ISoc2Rule[] = [
  {
    id: 'p7-001',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'Missing Data Accuracy Validation',
    description:
      'Personal data fields are written or updated without input-accuracy validation (format checks, range checks, or cross-field consistency checks). SOC2 P7.1 requires that entities maintain personal information that is accurate, complete, and current for its intended use. Persisting unvalidated data directly to storage creates permanent quality defects that may harm individuals and undermine audit evidence.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        'db\\.(?:save|insert|update|create|upsert)\\s*\\(|repository\\.save\\s*\\(|model\\.save\\s*\\(|collection\\.insertOne\\s*\\(|session\\.add\\s*\\(|em\\.persist\\s*\\(',
      flags: 'i',
      explanation:
        'Detects database-write calls (ORM save/insert/update/upsert, Mongoose save, SQLAlchemy session.add) that are not guarded by a preceding validation call such as validate(), isValid(), schema.parse(), or Joi/Zod/Yup validation. Files where write operations appear without any adjacent validation invocation on the same variable or object are flagged.',
    },
    remediation:
      'Apply schema-level validation before persisting any personal data record. Use a typed validation library (Zod, Yup, Joi, class-validator, Pydantic) to enforce format, range, and cross-field constraints. Reject and surface validation errors before the record reaches the data layer. Log rejected records with reason codes for audit purposes.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p7-002',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'No Data Freshness Checks',
    description:
      'The codebase reads and uses personal data records without verifying that those records are still current or within an acceptable age threshold. SOC2 P7.1 requires personal information to be kept current for its intended use. Consuming stale records — particularly for decisions affecting individuals (credit scoring, medical dosing, fraud detection) — can cause real-world harm and constitutes a data quality failure.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'updatedAt|updated_at|lastModified|last_modified|freshness|maxAge|max_age|dataAge|data_age|isFresh|is_fresh|staleness|refreshedAt|refreshed_at',
      flags: 'i',
      explanation:
        'Scans source files that query and consume personal data records for freshness-related field reads or freshness-guard conditions. Files that fetch user records and immediately use them for consequential decisions without any timestamp comparison or max-age guard are flagged.',
    },
    remediation:
      'Add an `updated_at` timestamp column to every personal data table. Before using a record in a consequential workflow, compare `updated_at` against a configured `maxAgeMs` threshold. Return an error or trigger a refresh workflow when the record exceeds the threshold. Document the acceptable freshness window for each data category in your data dictionary.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p7-003',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'Missing Stale Data Detection',
    description:
      'No automated mechanism exists to identify and flag personal data records that have not been updated within the expected update cycle. SOC2 P7.1 requires personal information to remain current; without scheduled staleness detection, stale records accumulate silently and risk being used in downstream processes without quality warnings.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'staleDataJob|stale_data_job|staleRecordScan|stale_record_scan|markStale|mark_stale|detectStale|detect_stale|staleness(?:Check|Monitor|Scan|Job)|STALE_THRESHOLD|stale_threshold',
      flags: 'i',
      explanation:
        'Searches the codebase and configuration files for scheduled jobs, cron entries, or background workers dedicated to detecting stale personal data records. Projects that store personal data but have no staleness-detection job, no stale-threshold constant, and no markStale/flag function are flagged.',
    },
    remediation:
      'Implement a scheduled staleness-detection job (e.g., a nightly cron) that queries personal data tables for records where `updated_at < NOW() - INTERVAL stale_threshold`. Mark flagged records with a `data_quality_flag = "stale"` column. Notify data stewards for review. Configure `stale_threshold` per data category in a central configuration file and document the rationale.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p7-004',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'No Data Completeness Metrics',
    description:
      'The system does not compute or expose completeness metrics for personal data records (e.g., percentage of required fields populated). SOC2 P7.1 requires personal information to be complete for its intended use. Without completeness metrics, the entity cannot demonstrate to auditors that records meet minimum quality thresholds required for lawful processing.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'completeness(?:Score|Metric|Check|Rate|Ratio)|data_completeness|dataCompleteness|completenessReport|nullRate|null_rate|missingFieldRate|missing_field_rate|recordCompleteness|profile_completeness',
      flags: 'i',
      explanation:
        'Looks for completeness-related metric computations, reporting functions, or configuration keys across the codebase. Projects that collect multi-field personal data records but never compute or surface a completeness score or null-rate metric are flagged.',
    },
    remediation:
      'Implement a data-completeness scoring module that calculates, for each personal data entity type, the percentage of required fields populated per record and the aggregate completeness rate across all records. Expose these metrics via an internal data-quality dashboard. Set minimum acceptable completeness thresholds per entity type in configuration and alert when thresholds are breached.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p7-005',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'Missing Data Deduplication',
    description:
      'The system creates or accumulates duplicate personal data records without a deduplication mechanism to detect and merge or remove them. SOC2 P7.1 requires accurate and complete personal information; duplicate records lead to inconsistencies, conflicting processing decisions, and difficulty honouring individual rights requests (deletion, correction) comprehensively.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'semgrep',
      value: `rules:
  - id: p7-005-missing-deduplication
    patterns:
      - pattern-either:
          - pattern: $DB.insert($DATA, ...)
          - pattern: $REPO.create($DATA, ...)
          - pattern: $COLLECTION.insertOne($DATA, ...)
          - pattern: $SESSION.add($OBJ)
      - pattern-not-inside: |
          ... deduplicate(...) ...
      - pattern-not-inside: |
          ... dedup(...) ...
      - pattern-not-inside: |
          ... findDuplicate(...) ...
      - pattern-not-inside: |
          ... upsert(...) ...
    message: >
      Personal data insert call has no preceding deduplication check.
      Duplicate records undermine P7.1 data quality requirements.
    languages: [javascript, typescript, python, java, go]
    severity: WARNING`,
      explanation:
        'Detects insert/create operations on data stores that are not guarded by a deduplication check (deduplicate, dedup, findDuplicate) or an upsert pattern. Raw inserts without prior duplicate detection are flagged as potential sources of duplicate personal data records.',
    },
    remediation:
      'Before inserting a new personal data record, query for existing records matching unique-identity fields (email, national ID, phone). If a duplicate exists, merge or update instead of creating a new record. Implement a periodic batch deduplication job for legacy data using probabilistic matching (fuzzy name + address). Add unique constraints on natural-key columns in the database schema.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p7-006',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'No Conflicting Data Resolution',
    description:
      'When personal data for the same individual exists in multiple systems or is updated from multiple sources, the codebase has no conflict-resolution strategy to determine which value is authoritative. SOC2 P7.1 requires that personal information used for processing be accurate; conflicting records without resolution logic leave the effective value undefined and non-deterministic.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'conflictResolution|conflict_resolution|resolveConflict|resolve_conflict|mergeStrategy|merge_strategy|lastWriteWins|last_write_wins|masterRecord|master_record|conflictPolicy|conflict_policy',
      flags: 'i',
      explanation:
        'Searches for conflict-resolution patterns in data-sync, ETL, and data-merge code paths. Codebases that write personal data from multiple upstream sources (webhooks, third-party sync, user self-service) without any conflict-resolution strategy, merge policy, or master-record designation are flagged.',
    },
    remediation:
      'Define and implement a conflict-resolution policy for each personal data attribute. Common strategies: last-write-wins with source priority ranking, user-authoritative (user\'s own submission always wins), or manual-review queue for unresolvable conflicts. Encode the chosen strategy in a `ConflictResolutionPolicy` configuration object. Log all resolved conflicts with before/after values for audit purposes.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p7-007',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'Missing Source of Truth Designation',
    description:
      'The codebase does not designate or enforce a single authoritative source of truth for personal data that appears in multiple systems or microservices. SOC2 P7.1 requires personal information to be accurate and current; without a designated source of truth, downstream consumers may read from inconsistent replicas and make decisions on inaccurate data.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'config'],
    pattern: {
      type: 'regex',
      value:
        'sourceOfTruth|source_of_truth|canonicalSource|canonical_source|goldenRecord|golden_record|masterDataSource|master_data_source|authoritative(?:Source|Store|Service)|primaryDataSource',
      flags: 'i',
      explanation:
        'Looks for constants, configuration keys, or annotation strings that designate a system or service as the authoritative source of truth for personal data entities. Projects that read personal data from multiple services with no canonical-source designation are flagged.',
    },
    remediation:
      'Document and enforce a source-of-truth designation for each personal data domain (identity, contact, preferences, etc.). Create a `DATA_SOURCES` configuration map that names the authoritative service for each domain. Ensure all read paths for consequential decisions query the authoritative source or a cache that is explicitly refreshed from it. Reference this map in your data architecture documentation.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p7-008',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'No Data Quality SLA Monitoring',
    description:
      'The system does not define or monitor Service Level Agreements (SLAs) for data quality dimensions such as accuracy rate, freshness, and completeness thresholds. SOC2 P7.1 requires ongoing maintenance of personal data quality; without measurable SLAs and monitoring, the entity cannot demonstrate continuous compliance or detect degradation in data quality over time.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'dataQualitySla|data_quality_sla|qualitySla|quality_sla|slaThreshold|sla_threshold|qualityTarget|quality_target|qualityKpi|quality_kpi|dataQualityBudget|error_budget.*quality|quality.*error_budget',
      flags: 'i',
      explanation:
        'Searches configuration files, monitoring setup code, and SLA definition modules for data-quality SLA thresholds or KPI targets. Projects that implement data-quality checks without formalised SLA targets or alert thresholds tied to those targets are flagged.',
    },
    remediation:
      'Define measurable data quality SLAs for each personal data category: e.g., accuracy rate >= 99%, completeness >= 95%, freshness within 24 hours. Encode these thresholds in a `dataQualitySla` configuration block. Instrument metrics collection to measure actual rates and compare against SLAs. Trigger alerts when SLAs are breached and report SLA compliance in regular data quality reviews.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p7-009',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'Missing Data Profiling',
    description:
      'The system does not perform data profiling to characterise the statistical distribution, value range, uniqueness, and null rates of personal data fields. SOC2 P7.1 requires entities to maintain data quality for its intended use; data profiling is the foundational mechanism for discovering quality defects such as unexpected nulls, outlier values, format violations, and cardinality anomalies before they propagate.',
    severity: 'low',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'dataProfil(?:e|ing|er)|data_profil(?:e|ing|er)|profileData|profile_data|columnStats|column_stats|fieldProfile|field_profile|computeStats|compute_stats|describeDataset|describe_dataset|qualityProfile',
      flags: 'i',
      explanation:
        'Looks for data-profiling function calls, classes, or module imports that compute per-column statistics on personal data tables or datasets. Projects that store structured personal data without any profiling module or profiling job invocation are flagged.',
    },
    remediation:
      'Implement or integrate a data-profiling step into your data pipelines. For each personal data table, compute: null rate, distinct value count, min/max/mean for numeric fields, format-conformance rate for strings (email regex, phone regex), and referential integrity rates. Run profiling on initial data loads and on a scheduled basis. Store profile results in a metadata catalogue for trend analysis.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p7-010',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'No Automated Data Quality Reports',
    description:
      'The system does not generate automated, recurring data quality reports for personal data holdings. SOC2 P7.1 mandates that entities maintain personal information quality for its intended use; automated reports are essential evidence of ongoing quality governance and enable timely identification and remediation of quality issues before they affect individuals.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'dataQualityReport|data_quality_report|qualityReport|quality_report|generateQualityReport|generate_quality_report|scheduleQualityReport|schedule_quality_report|dqReport|dq_report|sendQualityDigest|quality_digest',
      flags: 'i',
      explanation:
        'Searches for report-generation functions, scheduled report jobs, and report-dispatch logic dedicated to data quality. Codebases implementing data storage without any automated reporting mechanism for quality metrics are flagged.',
    },
    remediation:
      'Build or configure an automated data quality reporting pipeline that runs on a scheduled basis (weekly minimum). The report should cover: record counts, completeness rates, freshness distributions, deduplication status, validation failure rates, and SLA compliance. Distribute reports to data stewards and the privacy officer. Archive reports for SOC2 audit evidence.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p7-011',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'Missing User-Reported Inaccuracy Mechanism',
    description:
      'The application does not provide individuals with a mechanism to report inaccuracies in their personal data. SOC2 P7.1 requires that entities provide individuals with the ability to have inaccurate personal information corrected. Absence of an inaccuracy-reporting channel — distinct from a general correction request — means quality defects identified by the data subject cannot be efficiently routed to the responsible data steward.',
    severity: 'high',
    languages: ['typescript', 'javascript'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        'reportInaccuracy|report_inaccuracy|flagInaccuracy|flag_inaccuracy|dataCorrection(?:Request|Form|Flow)|data_correction_request|inaccuracyReport|inaccuracy_report|reportDataError|report_data_error|disputeData|dispute_data',
      flags: 'i',
      explanation:
        'Searches for UI components, API route handlers, and service methods that implement an inaccuracy-reporting or data-dispute flow. Projects that manage personal data in user-facing applications but have no inaccuracy-reporting endpoint, form component, or service function are flagged.',
    },
    remediation:
      'Add a "Report an inaccuracy" option to user profile pages and any view displaying personal data. Implement an API endpoint (e.g., POST /users/:id/data-corrections) that accepts a field name, incorrect value, and suggested correction. Route submissions to a data steward review queue. Acknowledge receipt to the user with a ticket reference and target resolution time. Log all corrections with before/after values for audit.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p7-012',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'No Data Quality Alerting',
    description:
      'The system does not emit alerts when data quality metrics fall below acceptable thresholds. SOC2 P7.1 requires entities to maintain personal information quality on an ongoing basis; without real-time or near-real-time alerting, quality degradation goes undetected until it causes harm, and the entity cannot demonstrate proactive quality governance to auditors.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'dataQualityAlert|data_quality_alert|qualityAlert|quality_alert|alertOnQuality|alert_on_quality|qualityThresholdBreached|quality_threshold_breached|dqAlert|dq_alert|qualityAlarm|quality_alarm|notifyDataQuality|notify_data_quality',
      flags: 'i',
      explanation:
        'Searches for alerting invocations, alert-configuration keys, and alert-handler registrations tied specifically to data quality metrics. Projects with data-quality checks but no alerting on threshold breaches are flagged.',
    },
    remediation:
      'Integrate data quality alerting into your monitoring stack (PagerDuty, Opsgenie, Slack, email). Define alert conditions for each SLA threshold: e.g., trigger a high-severity alert when completeness drops below 95%, a critical alert when duplicate rate exceeds 1%, or a warning when freshness exceeds the maximum age. Configure alert routing to the data steward on-call. Include runbooks for each alert type.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p7-013',
    criteria: 'P7.1',
    category: 'privacy',
    title: 'Missing Data Normalization Standards',
    description:
      'Personal data is stored and processed in non-normalised or inconsistently formatted forms (e.g., phone numbers in mixed formats, addresses without standardised components, names in mixed case). SOC2 P7.1 requires personal information to be maintained in a form suitable for its intended use; non-normalised data impedes accurate matching, deduplication, and rights fulfilment.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'semgrep',
      value: `rules:
  - id: p7-013-missing-normalization
    patterns:
      - pattern-either:
          - pattern: $OBJ.phone = $VAL
          - pattern: $OBJ.phoneNumber = $VAL
          - pattern: $OBJ.email = $VAL
          - pattern: $OBJ.address = $VAL
          - pattern: $OBJ.postalCode = $VAL
          - pattern: $OBJ.firstName = $VAL
          - pattern: $OBJ.lastName = $VAL
      - pattern-not-inside: |
          normalise(...)
      - pattern-not-inside: |
          normalize(...)
      - pattern-not-inside: |
          format(...)
      - pattern-not-inside: |
          sanitize(...)
    message: >
      Personal data field assigned without a preceding normalisation call.
      P7.1 requires consistent, normalised personal data for accurate processing.
    languages: [javascript, typescript, python, java, go]
    severity: WARNING`,
      explanation:
        'Identifies direct assignments to common personal data fields (phone, email, address, name components, postal code) that are not wrapped or preceded by a normalisation or formatting function. Raw user input assigned directly to these fields without normalisation is flagged.',
    },
    remediation:
      'Define and enforce normalisation standards for each personal data field type. Phone: store in E.164 format (+[country][number]); normalise on ingest using a library such as libphonenumber. Email: lowercase and trim. Address: apply address standardisation (USPS CASS, SmartyStreets, Google Address Validation). Name: trim whitespace, apply consistent case rules. Encode normalisation functions in a shared `dataNormalizer` module and call it before every write.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.nist.gov/cyberframework',
    ],
  },
];
