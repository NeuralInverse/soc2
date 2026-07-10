/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc7Rules: ISoc2Rule[] = [

	// ─── CC7.1 Vulnerability Detection (rules 001–008) ────────────────────────

	{
		id: 'cc7-001',
		criteria: 'CC7.1',
		category: 'security',
		title: 'Missing SAST tool in CI pipeline',
		description:
			'The CI/CD pipeline configuration does not invoke any Static Application Security Testing (SAST) tool, meaning code is deployed without automated vulnerability scanning and defects may reach production undetected.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:semgrep|sonarqube|sonar-scanner|snyk\\s+code|codeql|bandit|brakeman|gosec|spotbugs|checkmarx|veracode|fortify)',
			flags: 'i',
			explanation:
				'Flags CI pipeline definitions (GitHub Actions, GitLab CI, Jenkins, CircleCI) that contain no reference to a recognised SAST tool.',
		},
		remediation:
			'Integrate a SAST tool (e.g., Semgrep, CodeQL, or Snyk Code) as a required CI step that runs on every pull request. Fail the build when findings above a configured severity threshold are discovered.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc7-002',
		criteria: 'CC7.1',
		category: 'security',
		title: 'No dependency vulnerability scanning in CI pipeline',
		description:
			'The CI/CD pipeline does not run a software composition analysis (SCA) tool to detect known-vulnerable third-party dependencies, leaving the application exposed to published CVEs.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:npm\\s+audit|yarn\\s+audit|snyk\\s+test|dependabot|trivy\\s+fs|grype|osvscanner|pip-audit|safety\\s+check|owasp.dependency-check)',
			flags: 'i',
			explanation:
				'Flags CI pipeline files that contain no invocation of a dependency vulnerability scanner.',
		},
		remediation:
			'Add an SCA step (npm audit, Snyk, OWASP Dependency-Check, or Grype) to the pipeline. Configure alerts for critical and high severity CVEs and block merges until they are resolved.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc7-003',
		criteria: 'CC7.1',
		category: 'security',
		title: 'Missing DAST configuration or step',
		description:
			'No Dynamic Application Security Testing (DAST) configuration or pipeline step is present, meaning the running application is never probed for runtime vulnerabilities such as injection flaws or broken authentication.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:zap|owasp-zap|zaproxy|nuclei|nikto|burp|w3af|arachni|dast)',
			flags: 'i',
			explanation:
				'Flags pipeline or configuration files that contain no reference to a DAST tool or scan target URL.',
		},
		remediation:
			'Incorporate DAST into the pipeline using OWASP ZAP or Nuclei against a staging environment. Configure passive and active scanning policies and fail the pipeline on high-severity findings.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc7-004',
		criteria: 'CC7.1',
		category: 'security',
		title: 'No container image vulnerability scanning',
		description:
			'The Dockerfile or CI pipeline does not include a container image scanning step, allowing images with vulnerable OS packages or application dependencies to be pushed to the registry and deployed.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'dockerfile'],
		pattern: {
			type: 'absence',
			value: '(?:trivy\\s+image|grype|snyk\\s+container|docker\\s+scan|anchore|clair|twistlock|prisma\\s+cloud)',
			flags: 'i',
			explanation:
				'Flags CI pipeline and Dockerfile configurations that contain no container image scanning invocation.',
		},
		remediation:
			'Add a container image scan step after the docker build step using Trivy, Grype, or Snyk Container. Fail the pipeline when images contain critical or high CVEs. Enforce image signing and scanning policies in the container registry.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc7-005',
		criteria: 'CC7.1',
		category: 'security',
		title: 'Missing infrastructure-as-code security scanning',
		description:
			'Terraform, CloudFormation, or Kubernetes manifests are applied without a prior IaC security scan, allowing misconfigurations such as overly permissive security groups or disabled encryption to reach production infrastructure.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'iac'],
		pattern: {
			type: 'absence',
			value: '(?:tfsec|checkov|terrascan|kics|cfn-nag|cfn_nag|kubesec|kube-score|polaris)',
			flags: 'i',
			explanation:
				'Flags CI pipelines or IaC directories that contain no invocation of an IaC security scanner.',
		},
		remediation:
			'Integrate an IaC scanner (Checkov, tfsec, KICS) as a required CI step for all infrastructure changes. Enforce a baseline policy set and fail builds on critical misconfigurations before plan or apply.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc7-006',
		criteria: 'CC7.1',
		category: 'security',
		title: 'Secret scanning not configured in CI pipeline',
		description:
			'The CI/CD pipeline does not run a secret detection tool, allowing API keys, tokens, and credentials accidentally committed to the repository to flow undetected into builds and deployments.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:gitleaks|trufflesecurity|trufflehog|detect-secrets|secretlint|git-secrets|ggshield)',
			flags: 'i',
			explanation:
				'Flags CI pipeline definitions that contain no invocation of a secrets-scanning tool.',
		},
		remediation:
			'Add Gitleaks or TruffleHog to the CI pipeline as a pre-build gate. Also enable push-protection in GitHub Advanced Security or the equivalent in GitLab. Rotate any secrets that have already been exposed.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc7-007',
		criteria: 'CC7.1',
		category: 'security',
		title: 'Vulnerability scan results not retained or reported',
		description:
			'CI/CD pipeline scan steps run but their results are discarded (no artifact upload, no report path), preventing trend analysis and evidence collection required for SOC 2 audits.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:upload-artifact|artifacts:|reports:|junit|sarif|--output|--report|--format)',
			flags: 'i',
			explanation:
				'Flags pipeline files that run security tools but do not upload or persist their output as a pipeline artifact or report.',
		},
		remediation:
			'Configure scan tools to emit reports in SARIF, JUnit XML, or JSON format and upload them as pipeline artifacts. Integrate with GitHub Advanced Security, Defect Dojo, or a SIEM to retain findings for audit evidence.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-008',
		criteria: 'CC7.1',
		category: 'security',
		title: 'Penetration test schedule not referenced in configuration',
		description:
			'No scheduled external penetration test job, issue, or configuration reference is present in the codebase or CI system, indicating the absence of a recurring vulnerability assessment programme.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:pentest|penetration.test|vuln.assess|red.team|bug.bounty|external.scan)',
			flags: 'i',
			explanation:
				'Flags repositories that contain no evidence of a scheduled penetration testing or external vulnerability assessment programme.',
		},
		remediation:
			'Schedule at least one annual external penetration test and track it as a calendar event or CI scheduled job. Document findings, remediation timelines, and re-test results as audit evidence.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	// ─── CC7.2 Monitoring for Anomalies (rules 009–016) ──────────────────────

	{
		id: 'cc7-009',
		criteria: 'CC7.2',
		category: 'security',
		title: 'No structured logging — plain string log calls',
		description:
			'Application log output uses plain string interpolation (console.log, print, log.info with format strings) rather than structured JSON logging, making machine parsing, alerting, and SIEM ingestion unreliable.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:console\\.log\\s*\\(`|console\\.log\\s*\\(["\']|print\\s*\\(f["\']|logger\\.info\\s*\\(["\']|log\\.Printf\\s*\\("[^{])',
			flags: 'i',
			explanation:
				'Matches log calls that emit plain strings or template literals rather than structured objects, indicating unstructured logging.',
		},
		remediation:
			'Replace ad-hoc logging with a structured logging library (Pino, Winston, structlog, zerolog). Emit log records as JSON with fields: timestamp, level, message, service, traceId, and userId (if authenticated).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc7-010',
		criteria: 'CC7.2',
		category: 'security',
		title: 'Missing correlation / trace ID in request lifecycle',
		description:
			'HTTP request handlers do not generate or propagate a correlation or trace ID, making it impossible to link log entries from different services or layers to a single user transaction during incident investigation.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:correlationId|correlation_id|traceId|trace_id|requestId|request_id|x-request-id|x-trace-id|spanId)',
			flags: 'i',
			explanation:
				'Flags request handler code that processes incoming HTTP requests but never assigns or reads a correlation or trace identifier.',
		},
		remediation:
			'Generate a UUID correlation ID per request (or propagate the X-Request-ID header) and attach it to every log entry and outgoing service call. Use OpenTelemetry or a compatible tracing library for distributed tracing.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc7-011',
		criteria: 'CC7.2',
		category: 'security',
		title: 'Insufficient audit log fields — missing actor or resource',
		description:
			'Audit log entries are emitted but omit critical fields such as the actor (user ID, IP), the target resource, or the action taken, limiting the ability to reconstruct events during a security review.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'auditLog(?:\.log|\.write|\.record|\.emit)?\\s*\\(\\s*\\{[^}]*\\}\\s*\\)(?![\\s\\S]{0,300}(?:userId|user_id|actorId|actor_id|resourceId|resource_id|ipAddress|ip_address))',
			flags: 'i',
			explanation:
				'Detects audit log calls that emit an object literal missing essential actor, resource, and source-IP fields.',
		},
		remediation:
			'Standardise audit log entries with at minimum: actor (userId, roles), action, resource (type, id), outcome (success/failure), timestamp, and source IP. Enforce the schema with a TypeScript interface or Pydantic model.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-012',
		criteria: 'CC7.2',
		category: 'security',
		title: 'Log injection via unsanitised user input in log statement',
		description:
			'User-supplied data is interpolated directly into log messages without sanitisation, allowing an attacker to inject fake log entries, corrupt log structure, or exploit log parsers.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:logger|log|console)\\s*\\.(?:info|warn|error|debug|log)\\s*\\([^)]*(?:req\\.body|req\\.query|req\\.params|request\\.data|params\\[|input)',
			flags: 'i',
			explanation:
				'Matches log calls that embed unescaped request body, query, or parameter values directly in the log message.',
		},
		remediation:
			'Never interpolate raw user input into log messages. Log user-supplied values as separate structured fields. Strip or encode CRLF characters (\\r, \\n) and control characters before logging any external data.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc7-013',
		criteria: 'CC7.2',
		category: 'security',
		title: 'No security event logging on authentication failure',
		description:
			'Failed authentication attempts are not logged with sufficient context (actor, IP, timestamp), preventing detection of brute-force attacks or credential-stuffing campaigns through log analysis.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:AUTH_FAILURE|authentication.fail|login.fail|invalid.credential|wrong.password|authenticationError)',
			flags: 'i',
			explanation:
				'Flags authentication handler code that catches or returns failed-auth conditions without emitting a security event log entry.',
		},
		remediation:
			'Log every failed authentication attempt as a security event with: event type (AUTH_FAILURE), source IP, username (non-PII, hashed if required), timestamp, and request ID. Ship to a SIEM for alerting.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc7-014',
		criteria: 'CC7.2',
		category: 'security',
		title: 'No logging of privileged action execution',
		description:
			'Administrative or privileged operations (role changes, data exports, configuration updates) are executed without emitting a log record, making it impossible to detect insider threats or unauthorised admin activity.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:ADMIN_ACTION|privileged.action|admin.log|auditLog|audit_log|admin.event)',
			flags: 'i',
			explanation:
				'Flags admin route handlers that contain no security event or audit log call.',
		},
		remediation:
			'Wrap all privileged routes with an audit logging middleware that records: actor, action type, affected resource, before/after state snapshot (where feasible), and outcome. Store in an immutable log sink.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-015',
		criteria: 'CC7.2',
		category: 'security',
		title: 'Log retention or rotation policy not configured',
		description:
			'No log rotation, retention period, or archival policy is defined in the logging configuration, risking either disk exhaustion or premature deletion of evidence needed for incident investigations.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: '(?:maxFiles|maxSize|retentionDays|retention_days|log.retention|rotate|archiv)',
			flags: 'i',
			explanation:
				'Flags logging configuration files that define no retention period, file rotation, or archival policy.',
		},
		remediation:
			'Configure log rotation (daily or by size) and set a retention period of at least 90 days for operational logs and 12 months for security audit logs. Archive to immutable cold storage (S3 Object Lock, GCS with retention policy).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-016',
		criteria: 'CC7.2',
		category: 'security',
		title: 'Sensitive data included in application logs',
		description:
			'Log statements output raw sensitive fields such as passwords, tokens, credit card numbers, or PII, which then propagate to log aggregators and increase the blast radius of a log system compromise.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:logger|log|console)\\.(?:info|warn|error|debug|log)\\s*\\([^)]*(?:password|passwd|secret|token|ssn|credit.card|cvv|authorization)',
			flags: 'i',
			explanation:
				'Matches log calls that include sensitive field names in the logged data, indicating PII or credentials may be written to log files.',
		},
		remediation:
			'Implement a log-scrubbing layer that redacts sensitive fields before they are written. Define a denylist of field names (password, token, cvv) and replace values with [REDACTED]. Never log full request bodies without scrubbing.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
		],
	},

	// ─── CC7.3 Evaluated Security Events (rules 017–023) ─────────────────────

	{
		id: 'cc7-017',
		criteria: 'CC7.3',
		category: 'security',
		title: 'Missing incident response procedures reference',
		description:
			'The codebase or CI/CD configuration contains no reference to incident response runbooks, playbooks, or on-call escalation procedures, indicating the absence of a documented response process for security events.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:runbook|playbook|incident.response|on.call|pagerduty|opsgenie|victorops|escalation)',
			flags: 'i',
			explanation:
				'Flags CI/CD and configuration files that contain no reference to incident response documentation or on-call tooling.',
		},
		remediation:
			'Create and link incident response runbooks for common security events (data breach, DDoS, credential compromise). Integrate PagerDuty, OpsGenie, or equivalent on-call tooling. Reference the runbook URL in monitoring alert definitions.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-018',
		criteria: 'CC7.3',
		category: 'security',
		title: 'No alerting thresholds configured for error rates',
		description:
			'Monitoring or observability configuration files define metrics or dashboards but set no alert thresholds for error rates, latency spikes, or anomalous request volumes, meaning degraded security posture goes undetected.',
		severity: 'high',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: '(?:alert|threshold|alarm|notification|alerting|pagerduty|opsgenie|webhook.*alert)',
			flags: 'i',
			explanation:
				'Flags monitoring configuration files that define metrics or dashboards but contain no alerting rules or threshold definitions.',
		},
		remediation:
			'Define alert rules for: error rate > 1%, p99 latency > 2 s, authentication failure rate > 10/min, and 5xx responses > 5%. Route critical alerts to on-call via PagerDuty with escalation policies.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-019',
		criteria: 'CC7.3',
		category: 'security',
		title: 'Missing severity classification on thrown errors',
		description:
			'Error objects or exceptions are thrown without a severity or classification field, making it impossible for monitoring systems to triage events by impact or route them to the correct response team.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'throw\\s+new\\s+(?:Error|AppError|HttpError|ApiError)\\s*\\([^)]*\\)(?![\\s\\S]{0,100}(?:severity|level|code|type)\\s*[=:])',
			flags: 'i',
			explanation:
				'Matches error constructor calls that include a message argument but no severity, code, or classification property.',
		},
		remediation:
			'Define a custom error hierarchy with severity levels (CRITICAL, HIGH, MEDIUM, LOW). Include severity in every thrown error. Use error codes to map events to runbooks in your incident response tooling.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc7-020',
		criteria: 'CC7.3',
		category: 'security',
		title: 'No escalation policy defined for security alerts',
		description:
			'Alert or on-call configuration does not define an escalation policy, meaning unacknowledged critical security alerts are never routed to a secondary responder and may go unaddressed.',
		severity: 'high',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: '(?:escalation_policy|escalationPolicy|escalate_after|repeat_interval|escalation.rule)',
			flags: 'i',
			explanation:
				'Flags alert or on-call configuration files that define alert routing but contain no escalation policy.',
		},
		remediation:
			'Define escalation policies in PagerDuty, OpsGenie, or equivalent: acknowledge within 15 minutes or escalate to a secondary on-call and manager. Test escalation paths quarterly.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-021',
		criteria: 'CC7.3',
		category: 'security',
		title: 'Security events not forwarded to a SIEM',
		description:
			'Application and infrastructure logs are written locally but not shipped to a centralised Security Information and Event Management (SIEM) system, preventing cross-source correlation and real-time threat detection.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value: '(?:splunk|elastic|elasticsearch|datadog|sentinel|cloudwatch.logs|logstash|fluentd|siem|opensearch)',
			flags: 'i',
			explanation:
				'Flags infrastructure and application configuration files that contain no reference to a log shipping or SIEM integration.',
		},
		remediation:
			'Configure log shipping (Fluentd, Filebeat, CloudWatch agent) to forward all application, authentication, and audit logs to a SIEM. Define detection rules in the SIEM for known attack patterns and anomalies.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-022',
		criteria: 'CC7.3',
		category: 'security',
		title: 'Unhandled promise rejection swallows security events',
		description:
			'Unhandled promise rejections or uncaught exceptions in async code silently fail without logging or alerting, causing security events such as authorisation failures or database errors to disappear undetected.',
		severity: 'medium',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '\\.catch\\s*\\(\\s*(?:\\(\\s*\\)\\s*=>\\s*\\{\\s*\\}|\\(\\s*_\\s*\\)\\s*=>\\s*\\{\\s*\\}|err\\s*=>\\s*\\{\\s*\\})',
			flags: 'i',
			explanation:
				'Matches .catch() handlers with empty or no-op callbacks that discard errors silently.',
		},
		remediation:
			'Replace empty catch blocks with a handler that logs the error (with severity and context) and, for security-related operations, emits a security event. Set up process.on("unhandledRejection") as a global safety net.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc7-023',
		criteria: 'CC7.3',
		category: 'security',
		title: 'Security event evaluation lacking automated triage',
		description:
			'Security events are logged but there is no automated classification, deduplication, or priority assignment logic, requiring manual review of every event and increasing response time.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:triage|deduplicate|dedup|classify|prioritize|prioritise|eventScore|risk_score|severity_score)',
			flags: 'i',
			explanation:
				'Flags security event processing code that lacks automated triage, classification, or priority-scoring logic.',
		},
		remediation:
			'Implement event triage logic that scores events by type, frequency, and actor risk. Suppress duplicate events within a window. Automatically page on-call only for high/critical priority events to reduce alert fatigue.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	// ─── CC7.4 Security Incident Response (rules 024–030) ────────────────────

	{
		id: 'cc7-024',
		criteria: 'CC7.4',
		category: 'security',
		title: 'Missing incident response runbook links in alert definitions',
		description:
			'Alert definitions in monitoring configuration do not include a link to the corresponding incident response runbook, slowing down responder triage and increasing mean time to recover (MTTR).',
		severity: 'medium',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: '(?:runbook_url|runbookUrl|runbook:|wiki_url|docs_url|playbook_url)',
			flags: 'i',
			explanation:
				'Flags alert rule configuration files that define alert conditions but contain no runbook or playbook URL annotation.',
		},
		remediation:
			'Annotate every alert rule with a runbook_url pointing to the step-by-step response guide. Keep runbooks up to date and review them after every incident post-mortem.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-025',
		criteria: 'CC7.4',
		category: 'security',
		title: 'No automated breach detection for abnormal data exfiltration',
		description:
			'There is no code or configuration that monitors for abnormally large data exports, bulk record reads, or elevated API response sizes that may indicate data exfiltration in progress.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:exfiltration|dataExport.limit|exportThreshold|bulkDownload.alert|large.response.alert|byte.limit|row.limit)',
			flags: 'i',
			explanation:
				'Flags API or data export code that retrieves large amounts of data without any threshold check or anomaly-detection hook.',
		},
		remediation:
			'Implement anomaly detection for data access: alert when a single user exports more than N records per minute, or when response payload size exceeds a baseline by a configurable factor. Log and page on threshold breaches.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc7-026',
		criteria: 'CC7.4',
		category: 'security',
		title: 'Missing automated notification mechanism for critical incidents',
		description:
			'Critical error handling paths in the application do not trigger external notifications (email, Slack, webhook, SMS), meaning security-critical failures may go unnoticed until the next manual review.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:sendAlert|notify|notifyTeam|sendNotification|webhook\\.send|slack\\.post|email\\.send|sms\\.send|pagerduty\\.trigger)',
			flags: 'i',
			explanation:
				'Flags critical error handling blocks (catch for uncaught exceptions, process exit handlers) that do not trigger an external notification.',
		},
		remediation:
			'Instrument critical error paths to trigger an alert via PagerDuty, Slack, or email. Use a centralised alerting abstraction so the notification channel can be changed without modifying every call site.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc7-027',
		criteria: 'CC7.4',
		category: 'security',
		title: 'No forensic logging for database mutation operations',
		description:
			'Database writes and deletes are executed without emitting a forensic audit record capturing the before and after state, actor, and timestamp, preventing post-incident reconstruction of data changes.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:beforeImage|afterImage|old_values|new_values|delta|changeLog|change_log|mutation.log|forensic)',
			flags: 'i',
			explanation:
				'Flags ORM model hooks, database middleware, or repository classes that perform write operations without logging before/after state.',
		},
		remediation:
			'Implement a database change data capture (CDC) pattern: record old and new field values for every INSERT, UPDATE, and DELETE on sensitive tables. Store these records in an append-only audit table or event stream.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-028',
		criteria: 'CC7.4',
		category: 'security',
		title: 'Incident response without evidence preservation step',
		description:
			'Incident response code paths (error handlers, circuit breakers, kill switches) terminate processes or wipe state without first preserving diagnostic evidence such as heap dumps, request logs, or database snapshots.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:heapDump|thread.dump|snapshot|preserveEvidence|captureState|diagnostics\\.capture)',
			flags: 'i',
			explanation:
				'Flags incident-triggered shutdown or remediation handlers that perform no evidence-capture step before terminating or resetting application state.',
		},
		remediation:
			'Before terminating or resetting on a critical incident, capture a process snapshot (heap dump, goroutine dump, log flush) and write it to persistent storage. Automate evidence packaging for post-incident forensics.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-029',
		criteria: 'CC7.4',
		category: 'security',
		title: 'No post-incident review or retrospective hook',
		description:
			'Incident response workflows do not include an automated or tracked step for a post-incident review (PIR/post-mortem), resulting in repeated incidents due to un-addressed root causes.',
		severity: 'low',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:post.mortem|postmortem|post.incident.review|retrospective|lessons.learned|RCA|root.cause)',
			flags: 'i',
			explanation:
				'Flags incident management configuration and pipeline files that define no post-incident review or root cause analysis step.',
		},
		remediation:
			'Require a post-incident review within 48 hours of every severity-1 or severity-2 incident. Use an incident tracking tool (Jira, GitHub Issues) to track action items to completion.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-030',
		criteria: 'CC7.4',
		category: 'security',
		title: 'Incident containment lacks automated account suspension',
		description:
			'Incident response handlers do not include automated account suspension or credential revocation as a containment step, allowing an attacker who triggered the incident to continue accessing the system during the response period.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:suspendAccount|suspend_user|lockAccount|lock_account|disableUser|disable_user|revoke_all_tokens|emergencyRevoke)',
			flags: 'i',
			explanation:
				'Flags incident containment or response code paths that perform alerting or logging but include no automated account suspension or credential revocation.',
		},
		remediation:
			'Implement an emergency containment action that can suspend an account and revoke all active tokens with a single API call. Expose this through an incident response CLI tool or runbook automation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	// ─── CC7.5 Disclosure of Security Incidents (rules 031–035) ──────────────

	{
		id: 'cc7-031',
		criteria: 'CC7.5',
		category: 'security',
		title: 'Missing breach notification logic for affected users',
		description:
			'The codebase contains no function or service that sends breach notification messages to affected users, violating data-breach disclosure obligations under GDPR, CCPA, and similar regulations.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:breachNotif|breach_notif|notifyAffectedUsers|notify_affected|dataBreachEmail|data_breach_email|incidentDisclosure)',
			flags: 'i',
			explanation:
				'Flags codebases that handle user data but contain no function or module related to breach notification or user disclosure.',
		},
		remediation:
			'Implement a breach notification service that can identify affected accounts, compose a compliant disclosure email, and dispatch notifications within the regulatory deadline (72 hours for GDPR). Test the service annually.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc7-032',
		criteria: 'CC7.5',
		category: 'security',
		title: 'No stakeholder communication templates for security incidents',
		description:
			'The repository contains no communication templates, scripts, or content for notifying customers, partners, or board-level stakeholders during a security incident, increasing the risk of inconsistent or delayed disclosures.',
		severity: 'high',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: '(?:incident.template|communication.template|breach.template|notification.template|disclosure.template|status.page)',
			flags: 'i',
			explanation:
				'Flags configuration and documentation directories that contain no evidence of incident communication templates or status page integration.',
		},
		remediation:
			'Create and maintain communication templates for: (1) customer breach notification email, (2) internal incident declaration, (3) regulatory authority report, and (4) public status page post. Review templates annually.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc7-033',
		criteria: 'CC7.5',
		category: 'security',
		title: 'Missing regulatory reporting hook in incident pipeline',
		description:
			'The incident response pipeline or tooling contains no step that prompts for or automates submission to regulatory bodies (e.g., GDPR supervisory authority, HHS/OCR for HIPAA), risking late or missed mandatory reports.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:regulatory.report|gdpr.report|hipaa.report|dpa.report|ico.report|supervisory.authority|mandatory.report)',
			flags: 'i',
			explanation:
				'Flags incident management and CI/CD configurations that define no regulatory reporting step or checklist item.',
		},
		remediation:
			'Add a mandatory checklist item to the incident response runbook that requires the security lead to assess regulatory reporting obligations within 24 hours of incident detection. Automate deadline tracking in the incident ticket.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'cc7-034',
		criteria: 'CC7.5',
		category: 'security',
		title: 'Status page integration missing for public incident disclosure',
		description:
			'The application has no integration with a public or customer-facing status page service, making it impossible to rapidly communicate service disruptions or security incidents to users in a standardised way.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'source'],
		pattern: {
			type: 'absence',
			value: '(?:statuspage|status\\.io|cachet|atlassian\\.statuspage|betterstack|instatus|freshstatus)',
			flags: 'i',
			explanation:
				'Flags application and infrastructure configurations that contain no reference to a status page integration or public incident communication service.',
		},
		remediation:
			'Integrate with a status page provider (Atlassian Statuspage, BetterStack, Cachet). Automate component status updates from monitoring alerts. Include the status page URL in the incident response runbook.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'cc7-035',
		criteria: 'CC7.5',
		category: 'security',
		title: 'Incident disclosure deadline not enforced programmatically',
		description:
			'Incident management workflows do not track or enforce the 72-hour GDPR or applicable regulatory disclosure deadline programmatically, risking non-compliance through manual process failure.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:disclosureDeadline|disclosure_deadline|notificationDeadline|72.hour|seventy.two|reportBy|report_by|breachTimer)',
			flags: 'i',
			explanation:
				'Flags incident-tracking or notification code that manages breach events but contains no deadline calculation, countdown, or enforcement logic.',
		},
		remediation:
			'On breach incident creation, automatically calculate and store the regulatory disclosure deadline (detected_at + 72 hours for GDPR). Trigger escalating reminders at T-24 h and T-4 h. Block incident closure until disclosure is confirmed or a legal exemption is documented.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'cc7-036',
		criteria: 'CC7.2',
		category: 'security',
		title: 'Missing Structured Log Format',
		description:
			'Application log output is produced as unstructured plain-text strings rather than a structured format (JSON, logfmt). Unstructured logs cannot be reliably parsed, indexed, or queried by SIEM systems, making automated anomaly detection and security monitoring significantly less effective.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:winston|pino|bunyan|structlog|logrus|zap\\.New|zerolog|log4j2.*JsonLayout|JsonFormatter)',
			flags: 'i',
			explanation:
				'Detects the absence of a structured logging library. If no structured logger is referenced in source files, logs are likely emitted as plain text that cannot be reliably machine-parsed.',
		},
		remediation:
			'Adopt a structured logging library (pino or winston in Node.js, structlog in Python, logrus/zap in Go). Emit every log entry as a JSON object with mandatory fields: timestamp, level, service, traceId, and message. Forward logs to a centralised SIEM or log aggregation platform for alerting and anomaly detection.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
			'https://csrc.nist.gov/publications/detail/sp/800-92/final',
		],
	},

	{
		id: 'cc7-037',
		criteria: 'CC7.1',
		category: 'security',
		title: 'Container Image Scanned Without Failing on Critical CVEs',
		description:
			'The CI/CD pipeline runs a container image scanner (Trivy, Snyk, Grype) but does not configure an exit-code policy that fails the build on critical or high severity CVEs. Without a failing threshold, scan results are advisory only and vulnerable images can be promoted to production.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'regex',
			value: '(?:trivy image|snyk container test|grype)(?![^\\n]*(?:--exit-code\\s+1|--severity\\s+CRITICAL|fail-on|--fail-on))',
			flags: 'i',
			explanation:
				'Matches container scanning invocations that are not immediately followed on the same line by a failure-threshold flag. Indicates the scan runs but does not block the pipeline on findings.',
		},
		remediation:
			'Add `--exit-code 1 --severity CRITICAL,HIGH` to Trivy invocations, or the equivalent fail-on flag for your scanner. Store scan results as pipeline artefacts. Define a vulnerability management SLA (e.g., CRITICAL must be remediated within 24 hours) and enforce it via pipeline gates.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-devsecops-guideline/',
			'https://csrc.nist.gov/publications/detail/sp/800-190/final',
		],
	},

	{
		id: 'cc7-038',
		criteria: 'CC7.3',
		category: 'security',
		title: 'Missing Alerting Threshold on Error Rate',
		description:
			'Monitoring or observability configuration does not define an alert rule tied to application error rate or HTTP 5xx rate. Without error-rate alerting, spikes caused by active exploitation, infrastructure failures, or misconfigured deployments may go undetected until users report the issue.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'absence',
			value: '(?:error_rate|error.rate|5xx|http_errors|ErrorRate|alerting|alarmActions|alarm_actions)',
			flags: 'i',
			explanation:
				'Detects the absence of error-rate alerting configuration in monitoring, CloudWatch, Prometheus, or similar infrastructure-as-code files. If no error-rate threshold or alarm action is defined, error spikes produce no automated alert.',
		},
		remediation:
			'Define an alert rule that fires when the HTTP 5xx error rate exceeds an environment-appropriate threshold (e.g., >1% over 5 minutes for production). Route alerts to an on-call rotation via PagerDuty, OpsGenie, or equivalent. Review and tune thresholds quarterly to reduce noise while preserving signal.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
];
