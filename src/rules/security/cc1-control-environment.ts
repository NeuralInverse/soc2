/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc1Rules: ISoc2Rule[] = [
	// ── CC1.1 – Integrity and Ethical Values ─────────────────────────────────────

	{
		id: 'cc1-001',
		criteria: 'CC1.1',
		category: 'security',
		title: 'Missing Code-of-Conduct Reference in Configuration',
		description:
			'Project configuration files (package.json, pyproject.toml, pom.xml, go.mod, etc.) do not reference a code-of-conduct document. CC1.1 requires that the entity demonstrate a commitment to integrity and ethical values, which is typically evidenced by a published and referenced code of conduct.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: 'code.?of.?conduct|CODE_OF_CONDUCT|codeOfConduct',
			flags: 'i',
			explanation:
				'Checks that at least one config file contains a reference to a code-of-conduct artifact. Absence of any such reference indicates the control is not documented at the project level.',
		},
		remediation:
			'Add a CODE_OF_CONDUCT.md to the repository root and reference it from the primary project manifest (e.g., "bugs.url", "homepage", or a dedicated "conduct" key). Ensure the document is linked in contributing guidelines and that all contributors are required to acknowledge it.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'cc1-002',
		criteria: 'CC1.1',
		category: 'security',
		title: 'Hardcoded Admin Bypass Flag in Source Code',
		description:
			'Source code contains a hardcoded boolean or string constant that unconditionally bypasses administrative or authentication checks (e.g., `isAdmin = true`, `bypassAuth = true`, `SKIP_AUTH = true`). Such patterns undermine the ethical-values component of CC1.1 by allowing privileged access without proper authorization controls.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:const|let|var|val|final|static|private|public|protected)?\\s*(?:is_?admin|bypass_?auth|skip_?auth|admin_?override|force_?admin|debug_?admin)\\s*[=:]\\s*(?:true|True|TRUE|1|"true"|\'true\')',
			flags: 'i',
			explanation:
				'Matches variable declarations where an admin-bypass or auth-skip identifier is assigned a truthy literal. Flags patterns like `isAdmin = true`, `bypassAuth = true`, `SKIP_AUTH = 1` across multiple languages.',
		},
		remediation:
			'Remove all hardcoded bypass flags. Replace with runtime role checks sourced from a trusted identity provider or RBAC system. If debug flags are needed during development, gate them behind environment variables that are explicitly disallowed in production CI/CD pipelines.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	// ── CC1.2 – Board Oversight ───────────────────────────────────────────────────

	{
		id: 'cc1-003',
		criteria: 'CC1.2',
		category: 'security',
		title: 'Absence of Security Policy Documentation Reference',
		description:
			'No file in the repository references a formal information-security policy document. CC1.2 requires the board or equivalent governing body to oversee the design and implementation of security controls; the absence of a referenced security policy suggests that board-level oversight artifacts are not reflected in the codebase or its configuration.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value: 'security.?policy|SECURITY\\.md|infosec.?policy|information.?security.?policy',
			flags: 'i',
			explanation:
				'Checks for any reference to a SECURITY.md or analogous security-policy document in CI/CD pipelines and project configs. Absence signals missing board-oversight evidence.',
		},
		remediation:
			'Create a SECURITY.md at the repository root (following the GitHub security advisory standard) and reference it from CI/CD pipeline definitions. The document should include scope, roles, responsibilities, and escalation paths approved by the governing authority.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc1-004',
		criteria: 'CC1.2',
		category: 'security',
		title: 'Missing CISO or Security-Owner Role Assignment in IaC',
		description:
			'Infrastructure-as-Code templates (Terraform, CloudFormation, Pulumi, Bicep) do not assign a CISO, security-owner, or equivalent role binding. CC1.2 requires demonstrated board or senior-management oversight; the absence of a named security-owner role in cloud resource policies indicates that oversight accountability is not enforced at the infrastructure level.',
		severity: 'high',
		languages: ['any'],
		targets: ['iac'],
		pattern: {
			type: 'absence',
			value: 'ciso|security.?owner|security.?lead|infosec.?owner|security_contact',
			flags: 'i',
			explanation:
				'Checks IaC files for any assignment of a CISO or security-owner identity to a resource or IAM policy. Absence indicates that the infrastructure lacks a documented security-accountability binding.',
		},
		remediation:
			'Define an explicit security-owner tag or IAM role binding in all cloud resource templates. For example, add a `security_owner` tag to AWS/GCP/Azure resources and attach a policy granting the CISO read access to audit logs. Document the role in the organisation\'s RACI matrix.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	// ── CC1.3 – Organizational Structure ─────────────────────────────────────────

	{
		id: 'cc1-005',
		criteria: 'CC1.3',
		category: 'security',
		title: 'Hardcoded Superuser or Root Privilege Flag',
		description:
			'Source code assigns a hardcoded superuser, root, or god-mode privilege level to a user object or session context. CC1.3 requires that the organizational structure clearly segregates duties and restricts privileged access; hardcoded superuser flags circumvent this structure and violate the principle of least privilege.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:is_?super|is_?root|is_?god|super_?user|superuser|root_?access|god_?mode)\\s*[=:]\\s*(?:true|True|TRUE|1|"true"|\'true\')',
			flags: 'i',
			explanation:
				'Detects hardcoded superuser, root, or god-mode flag assignments in source code. Examples: `isSuperUser = true`, `root_access = True`, `godMode: true`.',
		},
		remediation:
			'Remove all hardcoded privilege escalation flags. Implement privilege checks through a centralised RBAC or ABAC service that reads roles from a trusted directory (e.g., Active Directory, Okta, AWS IAM). Enforce MFA for any privileged-role assumption and log all privilege escalation events.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc1-006',
		criteria: 'CC1.3',
		category: 'security',
		title: 'Missing RBAC Middleware or Role-Check in Route Definitions',
		description:
			'HTTP route or endpoint definitions do not include a role-based access control middleware, decorator, or guard. CC1.3 requires that the organisational structure enforces clear lines of authority and accountability; routes without RBAC checks allow any authenticated (or unauthenticated) user to invoke privileged operations.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: cc1-006-missing-rbac
    patterns:
      - pattern-either:
          - pattern: |
              $APP.get($PATH, $HANDLER)
          - pattern: |
              $APP.post($PATH, $HANDLER)
          - pattern: |
              $APP.put($PATH, $HANDLER)
          - pattern: |
              $APP.delete($PATH, $HANDLER)
          - pattern: |
              @GetMapping($PATH)
              $RETURN $METHOD(...) { ... }
          - pattern: |
              @PostMapping($PATH)
              $RETURN $METHOD(...) { ... }
      - pattern-not-inside: |
          ... requireRole(...) ...
      - pattern-not-inside: |
          ... authorize(...) ...
      - pattern-not-inside: |
          ... rbac(...) ...
      - pattern-not-inside: |
          ... @Roles(...) ...
      - pattern-not-inside: |
          ... @RequiresRoles(...) ...
    message: Route definition is missing RBAC middleware or role annotation.
    languages: [typescript, javascript, java]
    severity: WARNING`,
			explanation:
				'Semgrep rule that matches route handler registrations (Express-style and Spring-style) that lack any `requireRole`, `authorize`, `rbac`, `@Roles`, or `@RequiresRoles` guard in scope.',
		},
		remediation:
			'Apply an RBAC middleware or decorator to every route that performs a privileged operation. For Express, use a middleware like `express-jwt-permissions`; for Spring, use `@PreAuthorize("hasRole(\'ADMIN\')")`; for FastAPI, use dependency injection with a role-validation dependency.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc1-007',
		criteria: 'CC1.3',
		category: 'security',
		title: 'Wildcard IAM Policy Action Granting All Permissions',
		description:
			'IaC or Kubernetes manifests contain an IAM policy statement or RBAC role that grants a wildcard action (`"*"` or `"*:*"`). CC1.3 requires that organisational structure enforces role segregation and least-privilege access; wildcard permission grants collapse the intended role hierarchy and violate duty-separation requirements.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac', 'kubernetes'],
		pattern: {
			type: 'regex',
			value: '"Action"\\s*:\\s*(?:"\\*"|\\[\\s*"\\*"\\s*\\])|\\bactions\\s*=\\s*\\[\\s*"\\*"\\s*\\]|\\bverbs\\s*:\\s*\\[\\s*"\\*"\\s*\\]',
			flags: 'i',
			explanation:
				'Matches AWS IAM JSON policy `"Action": "*"`, Terraform `actions = ["*"]`, and Kubernetes RBAC `verbs: ["*"]` wildcard grants in IaC and Kubernetes manifest files.',
		},
		remediation:
			'Replace wildcard action grants with an explicit list of the minimum permissions required for the role to function. Follow the AWS IAM, GCP IAM, or Kubernetes RBAC least-privilege guidelines. Use permission boundaries or OPA/Gatekeeper policies to block wildcard grants in CI/CD pipelines.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	// ── CC1.4 – Commitment to Competence ─────────────────────────────────────────

	{
		id: 'cc1-008',
		criteria: 'CC1.4',
		category: 'security',
		title: 'Absence of Security Training Tracking Configuration',
		description:
			'No CI/CD pipeline or configuration file references a security-training tracker, LMS integration, or compliance-training check. CC1.4 requires that the entity demonstrate a commitment to attracting and developing competent individuals; the absence of any training-tracking reference suggests that security competence is not systematically verified before code is merged or deployed.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value:
				'security.?training|awareness.?training|lms.?check|training.?compliance|security.?certification|certif(?:ied|ication)',
			flags: 'i',
			explanation:
				'Checks CI/CD pipeline and project config files for any reference to security-training or certification tracking. Absence indicates no automated competence gate is in place.',
		},
		remediation:
			'Integrate a security-training verification step into the onboarding checklist and CI/CD pipeline. For example, add a pre-merge check that queries your LMS API (KnowBe4, Proofpoint, etc.) to confirm that the committer has completed mandatory security training within the past 12 months. Record completion in the employee directory.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc1-009',
		criteria: 'CC1.4',
		category: 'security',
		title: 'Hardcoded Developer Debug Credentials Indicating Untrained Usage',
		description:
			'Source code contains hardcoded developer-mode credentials or placeholder passwords that are characteristic of developers who have not been trained on secure-coding practices. Patterns such as `password = "dev"`, `apiKey = "test"`, or `secret = "changeme"` directly evidence a gap in security competence required by CC1.4.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value:
				'(?:password|passwd|pwd|api_?key|apikey|secret|token|credential)\\s*[=:]\\s*["\'](?:dev|test|demo|default|changeme|change_me|placeholder|dummy|example|admin|pass|1234|letmein|welcome|qwerty|abc123)["\']',
			flags: 'i',
			explanation:
				'Detects common placeholder or training-deficiency credential patterns where a sensitive field is assigned an obviously insecure literal string value.',
		},
		remediation:
			'Remove all hardcoded credentials immediately. Rotate any secrets that were committed. Inject credentials at runtime via environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or a Kubernetes secret mount. Add a pre-commit hook using `detect-secrets` or `trufflehog` to prevent future incidents.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc1-010',
		criteria: 'CC1.4',
		category: 'security',
		title: 'Missing Dependency Vulnerability Scanning in CI/CD Pipeline',
		description:
			'The CI/CD pipeline definition does not include a software-composition analysis (SCA) or dependency vulnerability scanning step. CC1.4 requires the entity to develop competent individuals and systems; the absence of automated dependency scanning reflects a gap in operational security competence and leaves known CVEs undetected.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value:
				'snyk|trivy|dependabot|grype|syft|npm audit|pip-audit|safety check|owasp dependency.?check|retire\\.js|audit',
			flags: 'i',
			explanation:
				'Checks CI/CD pipeline files for any reference to a known SCA tool or `audit` command. Absence indicates that dependency vulnerability scanning is not part of the automated build process.',
		},
		remediation:
			'Add a dependency vulnerability scanning step to every CI/CD pipeline. Use tools such as `npm audit --audit-level=high`, Snyk (`snyk test`), Trivy (`trivy fs .`), or OWASP Dependency-Check. Fail the build on critical or high severity findings. Configure Dependabot or Renovate for automated pull-request remediation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	// ── CC1.5 – Accountability ────────────────────────────────────────────────────

	{
		id: 'cc1-011',
		criteria: 'CC1.5',
		category: 'security',
		title: 'Missing Audit Log for Administrative Actions',
		description:
			'Administrative or privileged functions do not emit a structured audit log entry. CC1.5 requires that individuals are held accountable for their internal control responsibilities; without an audit trail for admin actions it is impossible to attribute changes to specific individuals or demonstrate accountability to auditors.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: cc1-011-missing-audit-log
    patterns:
      - pattern-either:
          - pattern: |
              function $ADMIN_FN(...) {
                ...
              }
          - pattern: |
              async function $ADMIN_FN(...) {
                ...
              }
          - pattern: |
              $OBJ.$ADMIN_FN = function(...) { ... }
      - metavariable-regex:
          metavariable: $ADMIN_FN
          regex: (?i)(delete|remove|drop|purge|reset|revoke|elevate|grant|promote|demote|disable|enable|ban|unban|impersonate)
      - pattern-not-inside: |
          ... auditLog(...) ...
      - pattern-not-inside: |
          ... audit.log(...) ...
      - pattern-not-inside: |
          ... logger.audit(...) ...
      - pattern-not-inside: |
          ... emit("audit",...) ...
    message: Administrative function is missing an audit log call.
    languages: [typescript, javascript]
    severity: WARNING`,
			explanation:
				'Semgrep rule that identifies functions with administrative names (delete, remove, drop, grant, revoke, etc.) that do not contain any call to an audit-logging function.',
		},
		remediation:
			'Add a structured audit log entry at the start and end of every administrative function. Include: timestamp (ISO 8601 UTC), actor identity, action performed, target resource identifier, source IP, and outcome (success/failure). Store audit logs in an append-only, tamper-evident store (e.g., AWS CloudTrail, Azure Monitor, immutable S3 bucket with Object Lock).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc1-012',
		criteria: 'CC1.5',
		category: 'security',
		title: 'Audit Log Writing to stdout Only Without Persistent Storage',
		description:
			'Logging configuration routes all audit events exclusively to stdout/stderr with no persistent sink (file, database, SIEM, or log-aggregation service). CC1.5 accountability requires that audit records be retained and retrievable; ephemeral container or process logs written only to stdout are lost on restart and cannot satisfy auditor evidence requests.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value:
				'(?:transport|sink|output|appender|handler)\\s*[=:]\\s*["\']?(?:console|stdout|stderr|process\\.stdout|process\\.stderr)["\']?(?:\\s*[,;\\}\\]]|$)',
			flags: 'im',
			explanation:
				'Detects logging transport/sink/appender configurations that point exclusively to console, stdout, or stderr, indicating no persistent log storage is configured.',
		},
		remediation:
			'Configure a persistent log transport in addition to (or instead of) stdout. For Winston, add a `File` or `Http` transport pointing to a log-aggregation service. For Python logging, add a `RotatingFileHandler` or a handler for your SIEM. Ensure log retention meets your compliance period (typically 1 year for SOC 2). Use log shipping agents (Fluentd, Filebeat) to forward to a centralised, tamper-evident store.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'cc1-013',
		criteria: 'CC1.5',
		category: 'security',
		title: 'Database Schema Missing Accountability Columns on Sensitive Tables',
		description:
			'Database migration or schema files define tables that store sensitive or administrative data but lack `created_by`, `updated_by`, `deleted_by`, or equivalent actor-tracking columns. CC1.5 requires that accountability is maintained for internal control actions; without actor attribution columns, database-level changes cannot be traced to specific individuals.',
		severity: 'low',
		languages: ['any'],
		targets: ['migration', 'schema'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: cc1-013-missing-accountability-columns
    patterns:
      - pattern: |
          CREATE TABLE $TABLE_NAME (
            ...
          );
      - metavariable-regex:
          metavariable: $TABLE_NAME
          regex: (?i)(user|account|admin|role|permission|audit|session|credential|token|secret|key|policy|config|setting)
      - pattern-not-inside: |
          CREATE TABLE $TABLE_NAME (
            ...
            created_by ...
            ...
          );
      - pattern-not-inside: |
          CREATE TABLE $TABLE_NAME (
            ...
            updated_by ...
            ...
          );
    message: Sensitive table is missing actor-attribution columns (created_by / updated_by).
    languages: [generic]
    severity: INFO`,
			explanation:
				'Semgrep generic rule that matches CREATE TABLE statements for tables with security-sensitive names and checks that they include `created_by` or `updated_by` accountability columns.',
		},
		remediation:
			'Add `created_by` (VARCHAR/UUID NOT NULL), `updated_by` (VARCHAR/UUID), and optionally `deleted_by` (VARCHAR/UUID) columns to all tables that store sensitive or administrative records. Populate these columns at the application layer using the authenticated user\'s identity. Ensure the columns are indexed and included in audit-report queries.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
];
