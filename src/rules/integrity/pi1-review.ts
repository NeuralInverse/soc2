/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const pi1ReviewRules: ISoc2Rule[] = [
	{
		id: 'pi1-rev-001',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'Missing Data Quality Monitoring',
		description:
			'No data quality monitoring instrumentation was detected. Processing integrity requires continuous monitoring of data quality metrics such as completeness, accuracy, and consistency. Without explicit quality checks the system cannot detect degraded data states before they propagate to downstream consumers.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:dataQuality|data_quality|qualityCheck|quality_check|DataQualityMonitor|qualityMetric|quality_metric|DQMonitor)',
			flags: 'i',
			explanation:
				'Detects the absence of any data quality monitoring identifiers in the codebase, indicating no programmatic quality tracking is in place.',
		},
		remediation:
			'Implement a data quality monitoring layer that tracks completeness (null/missing value rates), validity (schema conformance), consistency (cross-field rules), and timeliness (SLA windows). Emit quality metric events to an observability platform and alert on threshold breaches. Libraries such as Great Expectations (Python), deequ (JVM), or custom metric pipelines are acceptable. Metrics must be persisted and reviewable for audit purposes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'pi1-rev-002',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'No Data Anomaly Detection',
		description:
			'The codebase lacks anomaly detection logic for data processing pipelines. SOC 2 PI1.5 mandates that entities monitor processing results and detect deviations that could indicate corrupt, incomplete, or erroneous data. Absent anomaly detection, silent data corruption may go unnoticed for extended periods.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(?:anomaly[_\\s]?detect|AnomalyDetect|outlierDetect|outlier_detect|anomalyCheck|anomaly_check|detectAnomaly|detect_anomaly|StatisticalAnomal)',
			flags: 'i',
			explanation:
				'Searches for anomaly or outlier detection symbols. Their absence indicates the pipeline has no mechanism to flag statistically unusual processing results.',
		},
		remediation:
			'Integrate anomaly detection at critical pipeline stages. Statistical approaches (Z-score, IQR, moving-average deviation) or ML-based models should flag records or batch results that deviate from established baselines. Alert on detected anomalies with context (pipeline stage, record count, deviation magnitude) and route to an on-call queue. Document baseline calculation methodology and review periods.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'pi1-rev-003',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'Missing Integrity Check Scheduling',
		description:
			'No scheduled integrity verification jobs are configured. Periodic integrity checks (checksums, row-count reconciliations, hash verifications) must be run on a defined schedule to ensure stored and processed data has not drifted from its authoritative state. The absence of cron or scheduler entries for integrity jobs is a control gap.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(?:integrity[_\\-\\s]?check|checksum[_\\-\\s]?job|hash[_\\-\\s]?verify|reconcil[a-z]*[_\\-\\s]?schedule|data[_\\-\\s]?verify[_\\-\\s]?cron)',
			flags: 'i',
			explanation:
				'Looks for scheduler definitions referencing integrity checks or reconciliation jobs. Absence indicates no automated periodic integrity verification is configured.',
		},
		remediation:
			'Define a scheduled job (cron expression, CI/CD scheduled pipeline, or workflow scheduler) that executes integrity checks at minimum daily. Jobs should verify checksums of critical datasets, compare row counts across replicas, and validate referential constraints. Results must be logged, and failures must trigger alerts. Document the schedule, scope, and acceptance criteria in the runbook.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'pi1-rev-004',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'No Output Review Process',
		description:
			'Processing outputs are not subject to any review or validation gate before delivery to downstream systems or consumers. PI1.5 requires that output integrity is verified as part of the processing lifecycle. Without an output review step, erroneous or tampered data may be propagated and acted upon.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:outputReview|output_review|reviewOutput|review_output|outputValidat|output_validat|postProcessValidat|post_process_validat|deliveryCheck|delivery_check)',
			flags: 'i',
			explanation:
				'Identifies the absence of output review or post-processing validation logic, indicating data is dispatched to consumers without a review gate.',
		},
		remediation:
			'Introduce an output review stage after processing completes and before data is published or persisted. At a minimum the stage should: re-apply schema validation, check for unexpected nulls or sentinel values, confirm record counts match expectations from the input stage, and sign outputs with a verifiable checksum. Failed reviews must block delivery and raise an alert. Document the review criteria and acceptable tolerances.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},
	{
		id: 'pi1-rev-005',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'Missing Reconciliation Reporting',
		description:
			'No reconciliation reports are generated by the system. Reconciliation reporting provides a documented, time-stamped record that source data and processed output agree on counts, totals, and key fields. Without such reports auditors cannot verify that processing was complete and accurate over a given period.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(?:reconcili[a-z]*[_\\s]?report|ReconciliationReport|generateReconcil|generate_reconcil|reconcilReport|reconcil_report|balanceReport|balance_report)',
			flags: 'i',
			explanation:
				'Looks for reconciliation report generation logic. Absence means no automated reconciliation artifacts are produced for audit review.',
		},
		remediation:
			'Implement reconciliation report generation at the end of each processing run. Reports should capture: input record count vs. output record count, control totals (sums of key numeric fields), hash of the input dataset, hash of the output dataset, timestamp and pipeline run identifier, and any discrepancies with resolution status. Reports must be stored in an immutable audit log and made available to auditors on demand.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'pi1-rev-006',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'No Data Lineage Tracking',
		description:
			'Data lineage instrumentation is absent from the codebase. Lineage tracking records the origin, transformations, and destinations of data throughout the processing pipeline, enabling auditors and operators to trace data provenance and detect unauthorized mutations. Its absence is a critical gap in processing integrity assurance.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:lineage|dataLineage|data_lineage|LineageTrack|lineageTrack|provenance|dataProvenance|data_provenance|OpenLineage|lineageEvent)',
			flags: 'i',
			explanation:
				'Scans for data lineage or provenance tracking identifiers. Their absence indicates no lineage metadata is captured during data processing.',
		},
		remediation:
			'Adopt a data lineage framework (e.g., OpenLineage, Apache Atlas, or a custom event-based lineage model) and instrument all pipeline stages to emit lineage events. Each event should capture: dataset identifier, transformation applied, actor/service performing the operation, timestamp, and upstream/downstream dataset references. Store lineage metadata in a queryable store and expose a lineage API for audit and incident investigation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'pi1-rev-007',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'Missing Processing Log Completeness',
		description:
			'Processing logs lack completeness fields such as start time, end time, record counts, and status codes. Incomplete logs prevent post-hoc verification of whether a processing run fully executed or was interrupted, which is required to satisfy PI1.5 evidence requirements.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:log|logger|Logger)\\s*\\.(?:info|debug|warn|error)\\s*\\([^)]*\\)(?![\\s\\S]{0,300}(?:recordCount|record_count|rowsProcessed|rows_processed|processedCount|processed_count|itemCount|item_count|duration|elapsed|startTime|start_time|endTime|end_time))',
			flags: 'g',
			explanation:
				'Matches log statements that do not include completeness context fields (record counts, timing data) within a nearby code window, indicating log entries lack the structured data needed for audit evidence.',
		},
		remediation:
			'Adopt structured logging throughout processing pipelines. Each processing run log entry must include: run_id (UUID), pipeline_name, start_time (ISO 8601), end_time (ISO 8601), input_record_count, output_record_count, error_count, and status (success|partial|failed). Use a structured logger (e.g., pino, structlog, zap) and enforce the schema via a log schema validation step in CI.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'pi1-rev-008',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'No Automated Integrity Assertions',
		description:
			'Automated assertions that verify data invariants at processing boundaries are not present. Integrity assertions (e.g., assert total == expected, assert no_nulls(column)) act as executable specifications that halt processing when invariants are violated, preventing corrupted data from advancing through the pipeline.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:integrityAssert|integrity_assert|assertIntegrity|assert_integrity|DataAssertion|dataAssertion|data_assertion|assertDataQuality|assert_data_quality|IntegrityConstraint|integrityConstraint)',
			flags: 'i',
			explanation:
				'Searches for named integrity assertion constructs separate from generic unit test assertions. Their absence signals a lack of pipeline-embedded runtime invariant checks.',
		},
		remediation:
			'Embed integrity assertions at each pipeline stage boundary. Assertions should be expressed as executable, named checks (not ad-hoc conditionals) so they appear in logs and monitoring dashboards. Examples: assert_no_nulls(df, ["customer_id", "amount"]), assert_row_count_between(df, min=1, max=10_000_000), assert_sum_equals(df, "amount", expected_total). Failed assertions must raise a typed exception that triggers the incident management workflow.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},
	{
		id: 'pi1-rev-009',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'Missing Data Quality SLAs',
		description:
			'No data quality SLA definitions are present in configuration or source code. SLAs for data quality (e.g., maximum tolerable error rate, freshness window, minimum completeness percentage) are required to operationalize PI1.5 monitoring. Without defined SLAs, monitoring thresholds cannot be set and violations cannot be objectively identified.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value:
				'(?:qualitySla|quality_sla|dataSla|data_sla|sla[_\\s]?threshold|freshnessThreshold|freshness_threshold|completenessThreshold|completeness_threshold|errorRateThreshold|error_rate_threshold)',
			flags: 'i',
			explanation:
				'Checks configuration files for SLA threshold definitions related to data quality. Their absence means no formal quality service levels have been codified.',
		},
		remediation:
			'Define data quality SLAs in a configuration artifact (YAML, JSON, or code constants) and reference them in monitoring logic. Minimum SLA properties: max_error_rate (e.g., 0.001), min_completeness (e.g., 0.999), max_staleness_minutes (e.g., 60), min_record_count, and max_record_count. SLA definitions must be versioned, reviewed annually, and linked to alert rules in the observability platform. Document SLA rationale and sign-off in the change record.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'pi1-rev-010',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'No Integrity Dashboard Configuration',
		description:
			'No dashboard configuration for data integrity metrics was found. An integrity dashboard provides a centralised, real-time view of quality KPIs, anomaly signals, and SLA status, enabling operators and auditors to assess processing integrity at a glance. The absence of such configuration indicates integrity metrics are not surfaced for ongoing review.',
		severity: 'low',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'(?:integrityDashboard|integrity[_\\-]dashboard|dataquality[_\\-]dashboard|qualityDashboard|quality[_\\-]dashboard|grafana[^\\n]*integrity|datadog[^\\n]*integrity|integrity[^\\n]*panel)',
			flags: 'i',
			explanation:
				'Searches configuration and CI/CD files for references to integrity-specific dashboard panels or board definitions. Absence indicates no purpose-built integrity monitoring view exists.',
		},
		remediation:
			'Create a dedicated data integrity dashboard in your observability platform (Grafana, Datadog, Kibana, or equivalent). The dashboard must include: SLA compliance status per pipeline, anomaly detection alert history, reconciliation pass/fail trend, data freshness indicators, and error rate time-series. Export the dashboard definition as code (dashboard-as-code) and store it in the repository so changes are reviewed and auditable.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'pi1-rev-011',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'Missing Cross-System Reconciliation',
		description:
			'No cross-system reconciliation logic is present. When data flows between multiple systems (databases, message queues, APIs, data warehouses), each handoff creates an opportunity for data loss or duplication. Cross-system reconciliation compares counts and totals at both ends of each handoff and is essential for end-to-end processing integrity assurance.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: missing-cross-system-reconciliation
    patterns:
      - pattern: |
          $CLIENT.$METHOD(...)
      - pattern-not: |
          reconcile(...)
      - pattern-not: |
          crossSystemCheck(...)
      - pattern-not: |
          cross_system_check(...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: '^(send|publish|insert|write|push|produce|dispatch|forward)$'
    message: Data is being sent to an external system without a cross-system reconciliation call nearby.
    languages: [python, javascript, typescript, java, go]
    severity: ERROR`,
			explanation:
				'Uses semgrep to find outbound data transmission calls (send, publish, insert, write, push) that are not accompanied by a reconciliation call, indicating cross-system integrity verification is absent at the handoff point.',
		},
		remediation:
			'Implement a cross-system reconciliation routine that executes after every inter-system data transfer. The routine must: query both source and destination for the same key range, compare record counts and control totals, log and alert on discrepancies, and block subsequent pipeline stages until reconciliation passes or an operator acknowledges the deviation. Results must be stored in the audit log with source system, destination system, comparison window, and outcome.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'pi1-rev-012',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'No Integrity Alert Thresholds',
		description:
			'Alert threshold definitions for integrity metrics are missing from configuration. Without explicit thresholds, monitoring systems cannot raise alerts when data quality degrades. This creates a silent failure mode where integrity violations accumulate unnoticed. PI1.5 requires that deviations from expected processing results be detected and communicated promptly.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'regex',
			value:
				'(?:alert|alarm|monitor|notify)(?:[^\\n]{0,120}\\n){0,5}(?![^\\n]*(?:threshold|limit|min|max|percent|rate|count|window|period))',
			flags: 'gim',
			explanation:
				'Identifies alert or monitor configuration blocks that do not reference a numeric threshold or limit parameter, indicating alerts are defined without quantitative triggers.',
		},
		remediation:
			'For every integrity monitoring rule define explicit numeric thresholds: error_rate > 0.001 triggers WARNING, > 0.01 triggers CRITICAL; record_count_deviation > 5% triggers WARNING, > 20% triggers CRITICAL; freshness_lag > 60 minutes triggers WARNING, > 120 minutes triggers CRITICAL. Thresholds must be sourced from the SLA document (see pi1-rev-009), reviewed quarterly, and updated when baselines shift. Alert routing must reach an on-call engineer within the SLA response window.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'pi1-rev-013',
		criteria: 'PI1.5',
		category: 'integrity',
		title: 'Missing Periodic Integrity Audits',
		description:
			'No evidence of periodic integrity audit tasks or review checkpoints is present in the CI/CD pipeline or configuration. Periodic audits independently verify that monitoring controls, reconciliation processes, and data quality checks are functioning correctly. Their absence means the integrity control framework operates without self-validation, leaving systematic failures undetected.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(?:integrity[_\\-\\s]?audit|audit[_\\-\\s]?integrity|periodicAudit|periodic[_\\-]audit|data[_\\-\\s]?audit[_\\-\\s]?job|scheduled[_\\-\\s]?audit|audit[_\\-\\s]?schedule|auditCheck|audit_check)',
			flags: 'i',
			explanation:
				'Looks for periodic audit job definitions or scheduled audit task references in CI/CD and config files. Their absence indicates no automated periodic audit of the integrity control framework is scheduled.',
		},
		remediation:
			'Schedule a periodic integrity audit job that runs at minimum monthly (weekly recommended for high-volume pipelines). The audit job must: execute all integrity checks end-to-end against a production data sample, compare outputs against expected baselines recorded in the previous audit, verify that all alert thresholds fired correctly during the period by replaying historical anomaly events, and produce a signed audit report stored in the immutable audit log. Audit results must be reviewed by a designated data steward and any findings remediated within the defined SLA window.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
];
