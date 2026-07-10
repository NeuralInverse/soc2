/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc4Rules: ISoc2Rule[] = [
	// ── CC4.1 Ongoing Monitoring ──────────────────────────────────────────────────────────

	{
		id: 'cc4-001',
		criteria: 'CC4.1',
		category: 'security',
		title: 'Missing log aggregation configuration',
		description:
			'No centralised log aggregation sink (e.g. CloudWatch, Splunk, ELK, Loki, Datadog) is configured. ' +
			'Without aggregated logs, security events cannot be correlated or retained for review.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'absence',
			value:
				'(?i)(log_?aggregat|logging[._-]?endpoint|log[._-]?forwarder|log[._-]?shipper|' +
				'cloudwatch[._-]?logs|splunk[._-]?hec|logstash|fluentd|fluent[._-]?bit|loki|' +
				'datadog[._-]?logs|syslog[._-]?server|log[._-]?drain)',
			flags: 'i',
			explanation:
				'Checks for the absence of any recognised log aggregation configuration keyword. ' +
				'A match means no aggregation sink has been declared.',
		},
		remediation:
			'Configure a centralised log aggregation solution (e.g. AWS CloudWatch Logs, Elastic/ELK, ' +
			'Splunk HEC, Datadog, or Fluent Bit). Ensure all application, infrastructure, and security ' +
			'logs are shipped to this sink with adequate retention (≥ 90 days for SOC2).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc4-002',
		criteria: 'CC4.1',
		category: 'security',
		title: 'Alerting thresholds not defined',
		description:
			'Monitoring configuration lacks explicit alert threshold or alarm definitions. ' +
			'Without thresholds, anomalous activity will not trigger notifications, delaying incident response.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'absence',
			value:
				'(?i)(alarm[._-]?threshold|alert[._-]?threshold|threshold[._-]?value|' +
				'evaluation[._-]?period|comparison[._-]?operator|alarm[._-]?action|' +
				'alert[._-]?rule|alerting[._-]?rule|alert[._-]?condition|' +
				'metric[._-]?alarm|cloudwatch[._-]?alarm|prometheus[._-]?rule|' +
				'alertmanager|pagerduty|opsgenie)',
			flags: 'i',
			explanation:
				'Detects the absence of alert threshold configuration keywords across common monitoring ' +
				'platforms (CloudWatch, Prometheus AlertManager, PagerDuty, OpsGenie).',
		},
		remediation:
			'Define explicit alerting thresholds for key metrics: error rates, latency, CPU/memory ' +
			'utilisation, failed login attempts, and security group changes. Configure notification ' +
			'channels (email, Slack, PagerDuty) so on-call personnel receive timely alerts.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc4-003',
		criteria: 'CC4.1',
		category: 'security',
		title: 'Monitoring explicitly disabled in configuration',
		description:
			'A configuration key that controls monitoring, metrics collection, or observability has been ' +
			'set to a disabled/false/off value. This creates a blind spot that violates continuous monitoring obligations.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config', 'iac', 'kubernetes'],
		pattern: {
			type: 'regex',
			value:
				'(?i)(monitoring|metrics|observability|telemetry|tracing|profiling)[\\s\\S]{0,40}' +
				'[:=]\\s*(false|disabled?|off|0|no|"false"|\'false\'|"disabled"|\'disabled\')',
			flags: 'i',
			explanation:
				'Matches configuration assignments where a monitoring-related key is explicitly set ' +
				'to a falsy/disabled value within 40 characters of the key name.',
		},
		remediation:
			'Remove the disabled flag or set the value to true/enabled. Ensure metrics endpoints, ' +
			'tracing exporters, and health-check scrapers are active in all non-local environments. ' +
			'Gate any monitoring disable behind a feature flag that requires change-control approval.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc4-004',
		criteria: 'CC4.1',
		category: 'security',
		title: 'No liveness or readiness health check defined in Dockerfile',
		description:
			'The Dockerfile does not contain a HEALTHCHECK instruction. Without a health check the ' +
			'container runtime cannot detect application failures and orchestrators cannot route traffic away ' +
			'from degraded instances, undermining continuous availability monitoring.',
		severity: 'medium',
		languages: ['any'],
		targets: ['dockerfile'],
		pattern: {
			type: 'absence',
			value: '^HEALTHCHECK\\s',
			flags: 'im',
			explanation:
				'Checks that at least one HEALTHCHECK instruction exists at the start of a line in the Dockerfile.',
		},
		remediation:
			'Add a HEALTHCHECK instruction to the Dockerfile, e.g.: ' +
			'`HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8080/healthz || exit 1`. ' +
			'Align the health-check endpoint with your Kubernetes liveness/readiness probes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc4-005',
		criteria: 'CC4.1',
		category: 'security',
		title: 'Kubernetes deployment missing liveness probe',
		description:
			'A Kubernetes Deployment or StatefulSet container spec does not define a livenessProbe. ' +
			'Without it, Kubernetes cannot detect and restart hung processes, leaving unhealthy pods ' +
			'serving traffic and creating unmonitored failure states.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'absence',
			value: 'livenessProbe\\s*:',
			flags: 'i',
			explanation:
				'Checks for the absence of a livenessProbe key in Kubernetes manifest YAML. ' +
				'Missing probes indicate no ongoing container health monitoring.',
		},
		remediation:
			'Add a livenessProbe to every container spec in Deployments, StatefulSets, and DaemonSets. ' +
			'Use httpGet, tcpSocket, or exec checks against a dedicated /healthz endpoint. ' +
			'Set appropriate initialDelaySeconds, periodSeconds, and failureThreshold values.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc4-006',
		criteria: 'CC4.1',
		category: 'security',
		title: 'Log level set to suppress security-relevant events',
		description:
			'The application log level is configured to ERROR or FATAL/CRITICAL only, suppressing WARN ' +
			'and INFO events. Security monitoring depends on INFO-level audit events (logins, config changes, ' +
			'privilege escalations). Overly restrictive log levels create gaps in the audit trail.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'source'],
		pattern: {
			type: 'regex',
			value:
				'(?i)(log[._-]?level|logging[._-]?level|log[._-]?severity)' +
				'[\\s\\S]{0,20}[:=]\\s*["\']?(error|fatal|critical|CRITICAL|FATAL|ERROR)["\']?',
			flags: 'i',
			explanation:
				'Matches log-level configuration set to ERROR, FATAL, or CRITICAL, which suppresses ' +
				'INFO and WARN audit events necessary for security monitoring.',
		},
		remediation:
			'Set the log level to INFO (or DEBUG in development) so that authentication events, ' +
			'configuration changes, and access-control decisions are captured. ' +
			'Use structured logging and ship logs to the central aggregation sink.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc4-007',
		criteria: 'CC4.1',
		category: 'security',
		title: 'CI/CD pipeline missing monitoring or observability deployment step',
		description:
			'The CI/CD pipeline definition does not include a step that deploys, configures, or validates ' +
			'monitoring agents, dashboards, or alert rules. Changes shipped without corresponding monitoring ' +
			'updates can leave new code paths unobserved.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value:
				'(?i)(deploy[._-]?monitor|update[._-]?dashboard|push[._-]?dashboard|' +
				'grafana[._-]?deploy|datadog[._-]?monitor|newrelic[._-]?deploy|' +
				'prometheus[._-]?reload|alertmanager[._-]?reload|' +
				'monitoring[._-]?deploy|observability[._-]?step)',
			flags: 'i',
			explanation:
				'Detects the absence of any CI/CD step keyword related to deploying or validating ' +
				'monitoring configuration as part of the release pipeline.',
		},
		remediation:
			'Add a dedicated pipeline stage (e.g., "deploy-monitoring") that: pushes updated alert rules ' +
			'to Prometheus/AlertManager or Datadog, reloads Grafana dashboards, and validates that ' +
			'health-check endpoints return 200 before the deployment is marked successful.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc4-008',
		criteria: 'CC4.1',
		category: 'security',
		title: 'Metrics retention period below SOC2 minimum',
		description:
			'Monitoring or logging configuration specifies a retention period shorter than 90 days. ' +
			'SOC2 requires sufficient historical data to support periodic evaluations and incident investigations.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'regex',
			value:
				'(?i)(retention[._-]?(?:days?|period|duration)|log[._-]?retention|' +
				'metric[._-]?retention|storage[._-]?retention)[\\s\\S]{0,30}' +
				'[:=]\\s*["\']?([1-8]?[0-9])["\']?(?!\\d)',
			flags: 'i',
			explanation:
				'Matches retention configuration values between 1 and 89 (days), catching configurations ' +
				'that fall below the 90-day minimum commonly required for SOC2 evidence.',
		},
		remediation:
			'Increase retention to at least 90 days for operational logs and 365 days for security audit ' +
			'logs. For AWS CloudWatch, set retentionInDays ≥ 90. For Elasticsearch/OpenSearch, configure ' +
			'ILM policies accordingly. Document the retention policy in your security controls register.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	// ── CC4.2 Evaluations ─────────────────────────────────────────────────────────────────

	{
		id: 'cc4-009',
		criteria: 'CC4.2',
		category: 'security',
		title: 'No periodic review or scheduled evaluation mechanism detected',
		description:
			'The codebase or configuration contains no scheduled job, cron expression, or automated ' +
			'review trigger. CC4.2 requires that management periodically evaluates the effectiveness of ' +
			'controls; without scheduled reviews these evaluations may be skipped.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'cicd', 'source'],
		pattern: {
			type: 'absence',
			value:
				'(?i)(cron[._-]?schedule|scheduled[._-]?job|periodic[._-]?review|' +
				'review[._-]?schedule|audit[._-]?schedule|compliance[._-]?scan|' +
				'security[._-]?review|quarterly[._-]?review|monthly[._-]?review|' +
				'schedule\\s*:\\s*["\']?[0-9*])',
			flags: 'i',
			explanation:
				'Checks for the absence of any cron, scheduled-job, or periodic-review configuration ' +
				'keyword that would indicate automated control evaluations are in place.',
		},
		remediation:
			'Implement automated scheduled reviews using cron jobs, CI/CD scheduled pipelines, or ' +
			'workflow orchestration (e.g., GitHub Actions scheduled workflow, AWS EventBridge, Airflow). ' +
			'Schedule at minimum: weekly vulnerability scans, monthly access reviews, quarterly ' +
			'compliance assessments.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'cc4-010',
		criteria: 'CC4.2',
		category: 'security',
		title: 'Missing security audit schedule in CI/CD pipeline',
		description:
			'The CI/CD pipeline does not include a scheduled or triggered security audit step such as ' +
			'SAST, DAST, dependency scanning, or container image scanning. Without these automated ' +
			'evaluations, vulnerabilities may persist undetected between manual audits.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value:
				'(?i)(sast|dast|snyk|trivy|grype|anchore|clair|dependabot|' +
				'dependency[._-]?scan|security[._-]?scan|vuln[._-]?scan|' +
				'sonarqube|sonar[._-]?scan|semgrep|bandit|gosec|brakeman|' +
				'checkov|tfsec|kics|prowler|scout[._-]?suite)',
			flags: 'i',
			explanation:
				'Detects the absence of any recognised security scanning or audit tool invocation ' +
				'in the CI/CD pipeline definition file.',
		},
		remediation:
			'Integrate at least one SAST tool (e.g., Semgrep, SonarQube, Bandit) and one dependency ' +
			'scanner (e.g., Snyk, Dependabot, Trivy) into every pipeline. Add a container image scan ' +
			'(Trivy, Grype, or Anchore) to all Dockerfile build pipelines. Fail the pipeline on high/critical findings.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc4-011',
		criteria: 'CC4.2',
		category: 'security',
		title: 'Anomaly detection not configured',
		description:
			'No anomaly detection, outlier detection, or behavioural baseline configuration is present. ' +
			'CC4.2 requires that deviations from expected behaviour are identified; without anomaly ' +
			'detection, insider threats and zero-day exploits are likely to go unnoticed.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'absence',
			value:
				'(?i)(anomaly[._-]?detect|outlier[._-]?detect|behavioural[._-]?analytic|' +
				'behavioral[._-]?analytic|ueba|user[._-]?behav|baseline[._-]?alert|' +
				'ml[._-]?detect|machine[._-]?learning[._-]?alert|' +
				'guardduty|macie|security[._-]?hub|azure[._-]?sentinel|' +
				'aws[._-]?detective|chronicle|splunk[._-]?uba)',
			flags: 'i',
			explanation:
				'Checks for the absence of anomaly detection configuration keywords, covering both ' +
				'custom ML-based detections and managed cloud security services.',
		},
		remediation:
			'Enable a managed anomaly detection service appropriate to your environment: ' +
			'AWS GuardDuty + Security Hub, Azure Sentinel, or Google Chronicle. ' +
			'For on-premises, configure Splunk UBA or an ELK ML job. ' +
			'Define baselines for normal user and system behaviour and alert on deviations.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc4-012',
		criteria: 'CC4.2',
		category: 'security',
		title: 'Security event review automation disabled or absent',
		description:
			'Source code or configuration contains a pattern indicating that security event review or ' +
			'audit-log review is skipped, suppressed, or explicitly set to a no-op. ' +
			'This defeats the periodic evaluation requirement of CC4.2.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value:
				'(?i)(audit[._-]?review|security[._-]?review|event[._-]?review|' +
				'log[._-]?review)[\\s\\S]{0,60}' +
				'(=\\s*false|:\\s*false|disabled?|skip|bypass|noop|no[._-]?op|pass\\b)',
			flags: 'i',
			explanation:
				'Matches source or config patterns where an audit/security review function or flag ' +
				'is assigned a falsy, disabled, skip, or no-op value within 60 characters of the key.',
		},
		remediation:
			'Remove the disabled flag. Implement automated audit-log review using SIEM correlation rules, ' +
			'AWS Config rules, or a scheduled Lambda/Cloud Function that flags anomalies. ' +
			'Assign ownership of the review process to a named security role and document review cadence.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'cc4-013',
		criteria: 'CC4.2',
		category: 'security',
		title: 'Compliance or control evaluation results not persisted',
		description:
			'No configuration or code persists compliance scan results, control evaluation outputs, or ' +
			'audit findings to a durable store (S3, GCS, database, artifact registry). ' +
			'Without durable evidence, auditors cannot verify that evaluations occurred, ' +
			'and historical trend analysis is impossible.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'config', 'source'],
		pattern: {
			type: 'semgrep',
			value: [
				'rules:',
				'  - id: cc4-013-missing-compliance-artifact-upload',
				'    patterns:',
				'      - pattern-not: |',
				'          upload-artifact: ...',
				'      - pattern-not: |',
				'          aws s3 cp ...',
				'      - pattern-not: |',
				'          gsutil cp ...',
				'      - pattern-not: |',
				'          az storage blob upload ...',
				'    message: Compliance evaluation results are not uploaded to a durable artifact store.',
				'    languages: [yaml]',
				'    severity: WARNING',
			].join('\n'),
			explanation:
				'Semgrep rule that checks CI/CD YAML for the absence of artifact upload steps ' +
				'(GitHub Actions upload-artifact, AWS S3, GCS, or Azure Blob) after compliance scans.',
		},
		remediation:
			'After every compliance or security scan step, add an artifact upload action: ' +
			'use `actions/upload-artifact` in GitHub Actions, `aws s3 cp report.json s3://audit-bucket/` ' +
			'in shell steps, or equivalent for your CI platform. ' +
			'Retain these artifacts for at least one year to support SOC2 audit evidence requests.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
];
