/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc2Rules: ISoc2Rule[] = [
	// -------------------------------------------------------------------------
	// CC2.1 – Information Quality
	// -------------------------------------------------------------------------
	{
		id: 'cc2-001',
		criteria: 'CC2.1',
		category: 'security',
		title: 'Missing Input Validation on User-Supplied Data',
		description:
			'Functions or route handlers that accept external input without any validation allow untrusted data to flow into business logic, violating information quality requirements under CC2.1. Unvalidated inputs can corrupt internal state and undermine the accuracy of information used in decision-making.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:req\\.body|req\\.query|req\\.params)\\s*\\[?[\\w"\']+\\]?\\s*(?:=(?!=)|;|\\))',
			flags: 'g',
			explanation:
				'Detects direct reads of Express-style request properties (body, query, params) without an intermediate validation call such as a Joi/Zod schema parse, express-validator check, or similar guard before the value is used.',
		},
		remediation:
			'Validate all external inputs using a schema-validation library (e.g. Zod, Joi, class-validator) before the value is consumed. Reject requests that do not conform to the expected shape and log the violation for audit purposes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'cc2-002',
		criteria: 'CC2.1',
		category: 'security',
		title: 'Unvalidated Data Flow into Database Queries',
		description:
			'Raw user-supplied values passed directly into database query strings bypass input validation controls and degrade the integrity of persisted information. CC2.1 requires that the entity uses relevant, accurate information to support internal control.',
		severity: 'critical',
		languages: ['python'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: cc2-002-unvalidated-db-query
    patterns:
      - pattern: $CURSOR.execute($QUERY % $USER_INPUT)
      - pattern-not: $QUERY = "..."
    message: >
      User input is formatted directly into a SQL query string without
      parameterisation or prior validation.
    languages: [python]
    severity: ERROR`,
			explanation:
				'Matches Python database cursor.execute() calls where user-controlled data is interpolated into the query string via % or .format(), indicating absent input validation and integrity controls.',
		},
		remediation:
			'Use parameterised queries or an ORM (e.g. SQLAlchemy) and validate/sanitise all inputs through a schema (e.g. Pydantic) before they reach any database interaction layer.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},
	{
		id: 'cc2-003',
		criteria: 'CC2.1',
		category: 'security',
		title: 'Absence of Data Integrity Checks on Deserialized Objects',
		description:
			'Deserializing data without verifying a checksum, HMAC, or digital signature allows tampered payloads to enter the system undetected. This violates the CC2.1 requirement to process and retain complete, accurate information.',
		severity: 'high',
		languages: ['java'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:MessageDigest|HmacSHA|CRC32|Checksum|DigestUtils\\.(?:md5|sha)|\.verify\\()',
			flags: 'i',
			explanation:
				'Flags Java source files that contain ObjectInputStream or JSON deserialization calls but lack any reference to integrity-verification APIs (MessageDigest, HMAC, CRC32, etc.), indicating that deserialized data is trusted without verification.',
		},
		remediation:
			'Sign serialized payloads with an HMAC (e.g. HmacSHA256) keyed with a server-side secret. Verify the signature before deserializing and discard payloads whose signatures do not match.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'cc2-004',
		criteria: 'CC2.1',
		category: 'security',
		title: 'Schema Migrations Lack NOT NULL or CHECK Constraints',
		description:
			'Database migrations that add columns without NOT NULL or CHECK constraints allow incomplete or out-of-range data to be persisted, undermining the information quality controls required by CC2.1.',
		severity: 'medium',
		languages: ['any'],
		targets: ['migration'],
		pattern: {
			type: 'regex',
			value:
				'ADD\\s+COLUMN\\s+\\w+\\s+\\w+(?!\\s+NOT\\s+NULL)(?!\\s+CHECK\\s*\\()',
			flags: 'gi',
			explanation:
				'Detects SQL ALTER TABLE ADD COLUMN statements that do not include a NOT NULL constraint or a CHECK constraint immediately following the data type declaration.',
		},
		remediation:
			'Add NOT NULL constraints and, where applicable, CHECK constraints or ENUM types to every new column. Backfill existing rows before enabling the constraint so the migration is non-breaking.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	// -------------------------------------------------------------------------
	// CC2.2 – Internal Communication
	// -------------------------------------------------------------------------
	{
		id: 'cc2-005',
		criteria: 'CC2.2',
		category: 'security',
		title: 'No Security Alerting Integration Detected',
		description:
			'Application source files that handle authentication, authorisation, or error conditions but contain no calls to a security alerting or SIEM integration (e.g. PagerDuty, Datadog, Splunk, SNS) indicate that security-relevant events are not communicated internally in a timely manner, violating CC2.2.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:pagerduty|datadog|splunk|sentry|newrelic|cloudwatch|sns\\.publish|alert(?:ing)?\\.|notify(?:Security|Ops|Team)|securityEvent)',
			flags: 'i',
			explanation:
				'Scans source files for the absence of any reference to known alerting/SIEM integrations. Files that deal with auth or error handling should contain at least one such reference.',
		},
		remediation:
			'Integrate a centralized security alerting mechanism (e.g. Sentry, PagerDuty, Datadog) and emit structured security events for authentication failures, privilege escalations, and critical errors. Ensure alerts reach on-call personnel within defined SLOs.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'cc2-006',
		criteria: 'CC2.2',
		category: 'security',
		title: 'Hardcoded Email Addresses for Security Notifications',
		description:
			'Hardcoded email addresses in source code for routing security notifications are fragile and bypass formal communication channels. When personnel change, alerts may go undelivered, violating the internal communication controls in CC2.2.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'["\'][a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}["\']',
			flags: 'g',
			explanation:
				'Matches string literals that contain a fully-formed email address. Email addresses for security notifications should be resolved from environment variables or a configuration service, not embedded as literals.',
		},
		remediation:
			'Move notification recipients to environment variables or a configuration store (e.g. AWS SSM Parameter Store, HashiCorp Vault). Reference them at runtime so that changes to on-call rosters do not require code changes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'cc2-007',
		criteria: 'CC2.2',
		category: 'security',
		title: 'Missing Internal Security Channel Configuration in CI/CD Pipeline',
		description:
			'CI/CD pipeline definitions that lack any webhook, Slack, or notification configuration for security-related job failures mean that build-time security findings are not surfaced to engineering teams, violating the internal communication requirements of CC2.2.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value:
				'(?:slack|teams|webhook|notify|notification|pagerduty|opsgenie|victorops)',
			flags: 'i',
			explanation:
				'Detects CI/CD pipeline files (GitHub Actions, GitLab CI, CircleCI, etc.) that do not contain any notification or webhook integration, indicating that pipeline failures will not be communicated to the security or engineering team.',
		},
		remediation:
			'Add a notification step to every CI/CD pipeline that posts security-scan results and build failures to the designated security channel (e.g. Slack #security-alerts). Gate merges on passing security scans.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'cc2-008',
		criteria: 'CC2.2',
		category: 'security',
		title: 'Audit Log Events Not Forwarded to Centralized Log Aggregator',
		description:
			'Applications that write audit events only to local files or stdout without forwarding them to a centralized log aggregator risk losing security-relevant information and fail to meet the internal communication and monitoring requirements of CC2.2.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java'],
		targets: ['source', 'config'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: cc2-008-local-only-audit-log
    patterns:
      - pattern-either:
          - pattern: fs.appendFileSync($PATH, $MSG)
          - pattern: fs.writeFileSync($PATH, $MSG)
          - pattern: logging.basicConfig(filename=$F, ...)
      - pattern-not-inside: |
          $TRANSPORT = new $REMOTE(...)
          ...
    message: >
      Audit events are written to a local file only. Forward events to a
      centralized log aggregator (e.g. Elasticsearch, Splunk, CloudWatch Logs).
    languages: [javascript, typescript, python]
    severity: WARNING`,
			explanation:
				'Matches file-write calls used for logging that are not accompanied by a remote transport initialization, suggesting logs stay local and are never forwarded to a SIEM or log aggregator.',
		},
		remediation:
			'Configure a log-shipping agent (Fluentd, Logstash, CloudWatch agent) or use a logging library transport that sends structured audit events directly to a centralized aggregator. Retain logs for at least 12 months per SOC 2 requirements.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	// -------------------------------------------------------------------------
	// CC2.3 – External Communication
	// -------------------------------------------------------------------------
	{
		id: 'cc2-009',
		criteria: 'CC2.3',
		category: 'security',
		title: 'Missing Privacy Notice Reference in User-Facing Endpoints',
		description:
			'API responses or page controllers that collect personal data but contain no reference to a privacy policy URL or consent mechanism violate the external communication obligations of CC2.3, which requires the entity to communicate its privacy commitments to external parties.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:privacy[_\\-]?(?:policy|notice|url)|privacyUrl|PRIVACY_POLICY|consent(?:Text|Link|Url)|terms(?:Of(?:Service|Use)|Url))',
			flags: 'i',
			explanation:
				'Scans route handler and controller files for the absence of any reference to a privacy policy URL, notice, or consent mechanism. Presence of personal data fields (email, name, address) without these references is a CC2.3 gap.',
		},
		remediation:
			'Include a link to the current privacy notice in all user-facing responses that involve personal data collection. Implement a consent-capture mechanism and store user consent records for audit purposes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.iso.org/isoiec-27001-information-security.html',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'cc2-010',
		criteria: 'CC2.3',
		category: 'security',
		title: 'No Breach Notification Hook Implemented',
		description:
			'Systems that handle sensitive or personal data without a defined breach-notification function or integration violate CC2.3, which requires timely communication to external parties (regulators, customers) in the event of a security incident.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:breachNotif(?:y|ication)|incidentReport(?:er|ing)?|notifyDataSubjects|sendBreachAlert|reportIncident|breachHandler)',
			flags: 'i',
			explanation:
				'Checks for the complete absence of any breach-notification function name or integration hook across the codebase. A CC2.3-compliant system must have a documented and implemented path for notifying affected parties.',
		},
		remediation:
			'Implement a breach notification workflow that, when triggered, (1) notifies the designated privacy officer, (2) generates a timestamped incident record, and (3) sends regulated notifications to affected data subjects and supervisory authorities within the legally required window (e.g. 72 hours under GDPR).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'cc2-011',
		criteria: 'CC2.3',
		category: 'security',
		title: 'Insecure HTTP Used for External API Communication',
		description:
			'External HTTP calls made over plain http:// rather than https:// transmit data in cleartext, exposing it to interception. CC2.3 requires that communications with external parties protect the confidentiality and integrity of information in transit.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'https?://(?!localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)[^\'"\\s]+',
			flags: 'g',
			explanation:
				'Matches URL string literals that begin with http:// (not https://) and point to non-localhost hosts, indicating that external API calls are made over an unencrypted channel.',
		},
		remediation:
			'Replace all external http:// URLs with https://. Configure TLS certificate verification and enforce a minimum TLS version of 1.2 (preferably 1.3). Use HTTP Strict Transport Security (HSTS) for public-facing endpoints.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'cc2-012',
		criteria: 'CC2.3',
		category: 'security',
		title: 'TLS Certificate Verification Disabled in External Requests',
		description:
			'Disabling TLS certificate verification (e.g. verify=False in Python requests, rejectUnauthorized: false in Node.js) nullifies transport security guarantees and allows man-in-the-middle attacks on external communications, directly violating CC2.3 external communication integrity requirements.',
		severity: 'critical',
		languages: ['python', 'typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:verify\\s*=\\s*False|rejectUnauthorized\\s*:\\s*false|NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*["\']0["\']|ssl_verify\\s*=\\s*False)',
			flags: 'gi',
			explanation:
				'Detects common patterns that disable TLS/SSL certificate verification in Python (requests, httpx), Node.js (https module, axios), and environment variable overrides.',
		},
		remediation:
			'Remove all TLS verification bypass flags. Supply a trusted CA bundle if communicating with internal services that use a private CA. Never disable certificate verification in production code; use environment-specific configuration files to manage CA bundles.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},
	{
		id: 'cc2-013',
		criteria: 'CC2.3',
		category: 'security',
		title: 'External Webhook Payloads Not Signed or Verified',
		description:
			'Incoming webhook endpoints that accept external payloads without verifying a signature (e.g. HMAC-SHA256 header from GitHub, Stripe, or similar) allow arbitrary third parties to inject fraudulent events, undermining the authenticity of external communications required by CC2.3.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: cc2-013-unsigned-webhook
    patterns:
      - pattern-either:
          - pattern: |
              app.post($PATH, async ($REQ, $RES) => {
                ...
              })
          - pattern: |
              router.post($PATH, ($REQ, $RES) => {
                ...
              })
      - pattern-not-inside: |
          ...
          $SIG = $REQ.headers[...]
          ...
          crypto.timingSafeEqual(...)
          ...
    message: >
      Webhook handler does not verify an HMAC signature on the incoming
      payload. Unauthenticated webhooks allow event injection.
    languages: [javascript, typescript]
    severity: ERROR`,
			explanation:
				'Matches Express POST route handlers that handle webhook-style paths but do not contain a crypto.timingSafeEqual call for constant-time HMAC comparison, indicating the signature is either absent or improperly verified.',
		},
		remediation:
			'Verify all inbound webhook signatures using the provider-specified method (e.g. HMAC-SHA256 header). Use crypto.timingSafeEqual for comparison to prevent timing-oracle attacks. Reject and log any request whose signature does not match.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
];
