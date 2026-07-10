/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc3Rules: ISoc2Rule[] = [
	// ─── CC3.1 Risk Identification ────────────────────────────────────────────

	{
		id: 'cc3-001',
		criteria: 'CC3.1',
		category: 'security',
		title: 'Missing Threat Model Documentation',
		description:
			'No threat model file (THREAT_MODEL.md, threat-model.*, STRIDE.md, etc.) was found in the repository. ' +
			'CC3.1 requires entities to identify risks to the achievement of objectives, which includes documented threat modeling artifacts that enumerate attack surfaces and adversarial scenarios.',
		severity: 'high',
		languages: ['any'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: '(THREAT[_-]MODEL|threat-model|STRIDE|DREAD|PASTA|attack-surface|threat-modeling)\\.(md|yaml|yml|json|txt)$',
			flags: 'i',
			explanation:
				'Checks for the absence of any commonly named threat model artifact file. Triggers when no matching file is found in the repository root or docs/ directory.',
		},
		remediation:
			'Create a threat model document (e.g., THREAT_MODEL.md) in the repository root or a /docs directory. ' +
			'Use a structured methodology such as STRIDE, PASTA, or LINDDUN. The document must enumerate trust boundaries, ' +
			'data flows, threat actors, and mitigating controls. Review and update it at least annually or upon significant architectural changes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-threat-modeling/',
		],
	},

	{
		id: 'cc3-002',
		criteria: 'CC3.1',
		category: 'security',
		title: 'No Security Scanning Step in CI Pipeline',
		description:
			'The CI/CD pipeline definition does not include a dedicated security scanning step (SAST, DAST, secret scanning, or SCA). ' +
			'CC3.1 requires continuous identification of risks; automated security scans in the pipeline are a primary mechanism for identifying code-level vulnerabilities before deployment.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value:
				'(trivy|snyk|semgrep|sonarqube|sonar-scanner|bandit|gosec|brakeman|checkov|grype|anchore|trufflehog|gitleaks|detect-secrets|codeql|veracode|checkmarx|fortify|dependency-check)',
			flags: 'i',
			explanation:
				'Searches CI pipeline files (.github/workflows/*.yml, .gitlab-ci.yml, Jenkinsfile, .circleci/config.yml, azure-pipelines.yml) for invocations of well-known security scanning tools. Absence indicates no automated security scanning.',
		},
		remediation:
			'Integrate at least one SAST tool (e.g., Semgrep, CodeQL, SonarQube) and one SCA/dependency scanner (e.g., Trivy, Snyk, OWASP Dependency-Check) ' +
			'as mandatory pipeline steps. Configure the pipeline to fail on findings above an agreed severity threshold. ' +
			'Add secret scanning (e.g., TruffleHog, GitLeaks) as a pre-commit hook and pipeline gate.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-devsecops-guideline/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc3-003',
		criteria: 'CC3.1',
		category: 'security',
		title: 'Dependency Vulnerability Scanning Not Configured',
		description:
			'No dependency vulnerability scanning configuration (Dependabot, Renovate, npm audit, pip-audit, etc.) was detected. ' +
			'Third-party libraries are a primary attack surface; CC3.1 requires identifying risks from external components and supply-chain threats.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'(\\.github[\\/\\\\]dependabot\\.yml|renovate\\.json|\\.renovaterc|npm audit|pip-audit|bundle-audit|cargo audit|govulncheck|dependency-check|safety check)',
			flags: 'i',
			explanation:
				'Looks for dependabot.yml, renovate.json, or explicit audit commands in CI definitions. Absence means no automated dependency vulnerability management is in place.',
		},
		remediation:
			'Enable Dependabot (`.github/dependabot.yml`) or Renovate (`renovate.json`) for automated dependency updates. ' +
			'Add `npm audit --audit-level=high`, `pip-audit`, or equivalent as a mandatory CI step. ' +
			'Set a policy for maximum time-to-remediate critical/high CVEs (e.g., 7 days for critical, 30 days for high).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc3-004',
		criteria: 'CC3.1',
		category: 'security',
		title: 'Hardcoded Secrets or API Keys in Source Code',
		description:
			'Potential hardcoded credentials, API keys, or tokens were detected directly in source files. ' +
			'Exposed secrets represent an immediately exploitable risk that must be identified as part of CC3.1 risk identification processes.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|password|passwd|pwd)\\s*[=:]\\s*["\'][A-Za-z0-9+/\\-_]{16,}["\']',
			flags: 'i',
			explanation:
				'Matches assignment of string literals (16+ chars) to variables whose names suggest credential storage. Covers common naming patterns across multiple languages.',
		},
		remediation:
			'Remove all hardcoded secrets immediately. Rotate any exposed credentials. ' +
			'Use environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or a secrets injection tool. ' +
			'Enforce secret scanning as a pre-commit hook and CI gate to prevent future regressions.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	// ─── CC3.2 Risk Analysis ──────────────────────────────────────────────────

	{
		id: 'cc3-005',
		criteria: 'CC3.2',
		category: 'security',
		title: 'Missing CVSS Score Annotation on Known Vulnerability Suppressions',
		description:
			'Vulnerability suppression or ignore entries (in .snyk, .trivyignore, dependency-check suppression XML, etc.) lack CVSS score or risk justification comments. ' +
			'CC3.2 requires that identified risks be analyzed to determine their significance; undocumented suppressions bypass this analysis requirement.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'regex',
			value: '^\\s*-\\s*CVE-\\d{4}-\\d{4,}\\s*$',
			flags: 'gm',
			explanation:
				'Matches bare CVE identifiers (e.g., "- CVE-2021-44228") in suppression/ignore files without any accompanying CVSS score, justification, or expiry date on the same or adjacent line.',
		},
		remediation:
			'For every suppressed CVE, add an inline comment documenting: (1) CVSS base score, (2) business justification for suppression, ' +
			'(3) compensating controls in place, and (4) an expiry date for re-evaluation. ' +
			'Example: `# CVE-2021-44228 CVSS:10.0 – mitigated by WAF rule X; review by 2026-03-01`',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc3-006',
		criteria: 'CC3.2',
		category: 'security',
		title: 'No Risk Register Integration or Tracking Hook',
		description:
			'No evidence of risk register tooling, issue tracker integration, or structured risk tracking (e.g., risk labels in GitHub issues, JIRA risk components, or a RISK_REGISTER file) was found. ' +
			'CC3.2 requires that risks be analyzed and tracked; without a register, identified risks may not be systematically prioritized or assigned owners.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'source'],
		pattern: {
			type: 'absence',
			value:
				'(RISK[_-]REGISTER|risk-register|risk_register|RISKS\\.md|risks\\.md|risk-matrix|RISK[_-]MATRIX)\\.(md|yaml|yml|json|csv|txt)$',
			flags: 'i',
			explanation:
				'Checks for the absence of a risk register artifact file in the repository. A missing file indicates no structured risk tracking process is documented in the codebase or adjacent configuration.',
		},
		remediation:
			'Create a RISK_REGISTER.md or equivalent file at the repository root that captures each identified risk with: risk ID, description, likelihood, impact, CVSS or risk score, owner, response strategy, and review date. ' +
			'Alternatively, configure a dedicated risk label/component in your issue tracker and link it from the repository README. ' +
			'Review and update the register at least quarterly.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'cc3-007',
		criteria: 'CC3.2',
		category: 'security',
		title: 'Unrated Severity in Security Configuration',
		description:
			'Security policy or configuration files define rules or findings without specifying a severity level. ' +
			'CC3.2 requires risk analysis to determine the significance of each identified risk; rules without severity ratings make it impossible to prioritize remediation.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'regex',
			value: '"severity"\\s*:\\s*"(none|undefined|unknown|unspecified|tbd|todo|n\\/a)"',
			flags: 'i',
			explanation:
				'Matches JSON/YAML configuration entries where the severity field is explicitly set to a placeholder or null-equivalent value, indicating the risk has not been analyzed and rated.',
		},
		remediation:
			'Replace all placeholder severity values with a concrete rating from your approved taxonomy (e.g., critical/high/medium/low or CVSS numeric score). ' +
			'Establish a triage SLA: all newly detected findings must be rated within 48 hours. ' +
			'Reject CI pipeline runs that contain unrated findings.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc3-008',
		criteria: 'CC3.2',
		category: 'security',
		title: 'Security Scan Results Not Failing the Build on High/Critical Findings',
		description:
			'CI pipeline invokes security scanning tools but does not configure them to fail the build on high or critical severity findings. ' +
			'This means identified risks are surfaced but not acted upon, violating CC3.2 risk analysis requirements that risks be evaluated and responded to appropriately.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'regex',
			value:
				'(trivy|snyk|semgrep|bandit|gosec|checkov|grype)\\b(?:(?!(?:--exit-code\\s+[1-9]|--severity\\s+(?:HIGH|CRITICAL)|fail-on|--fail-on|exit_zero\\s*=\\s*false)).)*$',
			flags: 'gim',
			explanation:
				'Matches security tool invocations in CI files where no non-zero exit code or severity threshold flag is specified, indicating scans run in report-only mode without blocking the pipeline.',
		},
		remediation:
			'Configure security scanning tools with exit-on-failure flags: `trivy --exit-code 1 --severity HIGH,CRITICAL`, `snyk test --severity-threshold=high`, ' +
			'`semgrep --error`. Establish a break-glass process for emergency overrides with mandatory post-incident review.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-devsecops-guideline/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	// ─── CC3.3 Risk Response ──────────────────────────────────────────────────

	{
		id: 'cc3-009',
		criteria: 'CC3.3',
		category: 'security',
		title: 'No Automated Vulnerability Remediation Workflow',
		description:
			'No automated remediation workflow (e.g., auto-merge Dependabot PRs for patch-level updates, automated hotfix pipeline, or remediation runbooks) was detected. ' +
			'CC3.3 requires that the entity respond to identified risks; automated workflows ensure timely remediation of known vulnerabilities.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(auto[_-]?merge|automerge|auto[_-]?fix|autofix|remediat|hotfix[_-]pipeline|patch[_-]automation|REMEDIATION|remediation[_-]runbook)',
			flags: 'i',
			explanation:
				'Looks for auto-merge configurations in Dependabot/Renovate settings or pipeline files, and remediation runbook documents. Absence indicates manual-only remediation processes.',
		},
		remediation:
			'Configure Dependabot or Renovate to auto-merge patch-level dependency updates after CI passes. ' +
			'Create a documented remediation runbook (REMEDIATION_RUNBOOK.md) that specifies SLAs, escalation paths, and rollback procedures for each severity level. ' +
			'Automate patch deployment pipelines for critical CVEs with an SLA of 24 hours.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc3-010',
		criteria: 'CC3.3',
		category: 'security',
		title: 'Missing Security Gate Before Production Deployment',
		description:
			'The deployment pipeline does not enforce a mandatory security approval gate or quality gate before promoting artifacts to production. ' +
			'CC3.3 requires that risk responses include controls that reduce risks to acceptable levels; a missing production security gate allows unreviewed changes to reach production.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value:
				'(environment\\s*:\\s*production|deploy[_-]?to[_-]?prod|production[_-]?deploy)(?:[\\s\\S]{0,500}?)(security[_-]?gate|security[_-]?approval|required[_-]?reviewers|protection[_-]?rules|manual[_-]?approval|gates)',
			flags: 'i',
			explanation:
				'Checks for production deployment steps that are not preceded or accompanied by a security gate, approval step, or branch protection reference within a reasonable proximity of lines.',
		},
		remediation:
			'Add an environment protection rule for the production environment requiring at least one security team reviewer approval before deployment. ' +
			'In GitHub Actions, use `environment: production` with required reviewers. In GitLab, use protected environments. ' +
			'In Jenkins, add an `input` step with security sign-off. Document the gate criteria in your deployment runbook.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc3-011',
		criteria: 'CC3.3',
		category: 'security',
		title: 'Infrastructure as Code Deployed Without Security Policy Validation',
		description:
			'IaC files (Terraform, CloudFormation, Pulumi, ARM) are present but the pipeline does not include a policy-as-code validation step (Checkov, OPA, tfsec, cfn-nag). ' +
			'CC3.3 risk response requires validating that infrastructure changes do not introduce new risks before they are applied.',
		severity: 'high',
		languages: ['any'],
		targets: ['iac', 'cicd'],
		pattern: {
			type: 'absence',
			value: '(checkov|tfsec|terrascan|cfn-nag|cfn_nag|opa eval|conftest|kics|snyk iac)',
			flags: 'i',
			explanation:
				'Searches IaC-adjacent pipeline files for policy-as-code tool invocations. When IaC files exist but no policy validation tool is found in the pipeline, the rule triggers.',
		},
		remediation:
			'Add `checkov -d . --framework terraform` or `tfsec .` as a mandatory step in the IaC deployment pipeline. ' +
			'Configure OPA/Conftest with organization-specific policies. Set the step to fail on HIGH or CRITICAL policy violations. ' +
			'Maintain a curated policy library covering CIS Benchmarks for your cloud provider.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.cisecurity.org/cis-benchmarks',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc3-012',
		criteria: 'CC3.3',
		category: 'security',
		title: 'Exception or Error Swallowing Prevents Risk Signal Propagation',
		description:
			'Broad catch-all exception handlers that silently discard errors prevent security-relevant failures from being recorded or escalated. ' +
			'CC3.3 risk response depends on accurate risk signals; swallowed exceptions suppress the data needed to detect and respond to incidents.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'catch\\s*(?:\\([^)]*\\))?\\s*\\{\\s*(?:\\/\\/[^\\n]*\\n\\s*)?\\}|except\\s+(?:Exception|BaseException)\\s*(?:as\\s+\\w+)?\\s*:\\s*pass',
			flags: 'gm',
			explanation:
				'Matches empty catch blocks in TypeScript/JavaScript/Java/C# and bare `except: pass` or `except Exception: pass` patterns in Python, which silently swallow all exceptions without logging or re-throwing.',
		},
		remediation:
			'Replace empty catch blocks with explicit error handling: log the error at WARN or ERROR level with structured context, ' +
			'emit a metric or alert, and re-throw or return a typed error. ' +
			'Use a global error handler / middleware for unhandled rejections and configure alerting for unexpected error spikes.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc3-013',
		criteria: 'CC3.3',
		category: 'security',
		title: 'Container Image Not Pinned to Digest in Production Deployment',
		description:
			'Container images in Kubernetes manifests or Dockerfiles use mutable tags (e.g., `:latest`, `:stable`, `:main`) rather than immutable SHA256 digests. ' +
			'This introduces supply-chain risk because the image content can change between deployments, undermining CC3.3 risk response guarantees.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes', 'dockerfile', 'iac'],
		pattern: {
			type: 'regex',
			value:
				'image\\s*:\\s*["\']?[a-z0-9][a-z0-9._\\-/]*(?::[a-z0-9._\\-]+)?(?<!@sha256:[a-f0-9]{64})["\']?\\s*$',
			flags: 'gim',
			explanation:
				'Matches image references in Kubernetes manifests and Compose files that do not end with an `@sha256:<digest>` pin, indicating mutable tag usage.',
		},
		remediation:
			'Pin all production container images to their SHA256 digest: `image: myapp@sha256:abc123...`. ' +
			'Use tools like `crane digest` or `docker inspect` to retrieve digests. ' +
			'Automate digest updates via Renovate or a custom pipeline step, and sign images with Cosign for supply-chain integrity.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.cisecurity.org/cis-benchmarks',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	// ─── CC3.4 Change Risk ────────────────────────────────────────────────────

	{
		id: 'cc3-014',
		criteria: 'CC3.4',
		category: 'security',
		title: 'Pull Request Template Missing Risk Assessment Section',
		description:
			'The repository pull request template does not include a security risk assessment section prompting authors to evaluate the risk of their changes. ' +
			'CC3.4 requires that risks from changes be assessed; without a structured prompt, risk assessment is inconsistently applied.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value:
				'(security[\\s_-]?risk|risk[\\s_-]?assessment|security[\\s_-]?review|threat[\\s_-]?model|security[\\s_-]?impact|security[\\s_-]?checklist)',
			flags: 'i',
			explanation:
				'Checks that pull request template files (.github/PULL_REQUEST_TEMPLATE.md, .gitlab/merge_request_templates/*.md) contain a security risk assessment or security checklist section.',
		},
		remediation:
			'Add a "Security Risk Assessment" section to your PR template with checklist items such as: ' +
			'[ ] Does this change affect authentication or authorization logic? ' +
			'[ ] Does this change handle sensitive data? ' +
			'[ ] Has a threat model been updated? ' +
			'[ ] Has security scanning passed? ' +
			'Make the checklist mandatory by adding a CODEOWNERS rule requiring security team review when the checklist indicates risk.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-devsecops-guideline/',
		],
	},

	{
		id: 'cc3-015',
		criteria: 'CC3.4',
		category: 'security',
		title: 'No CODEOWNERS File Requiring Security Review for Sensitive Paths',
		description:
			'The repository lacks a CODEOWNERS file or the existing CODEOWNERS does not assign a security team as required reviewer for sensitive paths ' +
			'(authentication, authorization, cryptography, secrets management, IAM). ' +
			'CC3.4 requires that high-risk changes receive appropriate review; CODEOWNERS is the enforcement mechanism for this control.',
		severity: 'high',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value:
				'(auth(?:entication|orization|[^o])|crypto|secret|iam|permission|privilege|access[_-]?control|security)',
			flags: 'i',
			explanation:
				'Checks that the CODEOWNERS file (.github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS) contains at least one entry mapping security-sensitive path patterns to a security team or individual.',
		},
		remediation:
			'Create or update `.github/CODEOWNERS` to assign `@security-team` (or equivalent) as a required reviewer for sensitive directories: ' +
			'`/src/auth/ @security-team`, `/src/crypto/ @security-team`, `/infra/ @security-team @infra-team`. ' +
			'Enable branch protection rules that enforce CODEOWNERS review before merge.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc3-016',
		criteria: 'CC3.4',
		category: 'security',
		title: 'Database Schema Migration Without Rollback Script',
		description:
			'Database migration files contain irreversible operations (DROP TABLE, DROP COLUMN, ALTER COLUMN with type change) without a corresponding down/rollback migration. ' +
			'CC3.4 requires risk assessment of changes; irreversible migrations represent high-impact change risk if a deployment must be rolled back.',
		severity: 'high',
		languages: ['any'],
		targets: ['migration'],
		pattern: {
			type: 'regex',
			value:
				'^\\s*(?:DROP\\s+(?:TABLE|COLUMN|INDEX|CONSTRAINT)|ALTER\\s+TABLE\\s+\\S+\\s+(?:DROP|RENAME|ALTER\\s+COLUMN))',
			flags: 'gim',
			explanation:
				'Matches destructive or potentially irreversible DDL statements in migration files. These require explicit rollback scripts to satisfy change risk assessment requirements.',
		},
		remediation:
			'For every destructive migration, create a corresponding rollback migration that restores the previous state. ' +
			'Use expand-contract patterns: add new columns/tables before removing old ones. ' +
			'Test rollback procedures in staging before production deployment. ' +
			'Require DBA or platform team approval for migrations containing DROP or destructive ALTER statements.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc3-017',
		criteria: 'CC3.4',
		category: 'security',
		title: 'Feature Flags Not Used for High-Risk Feature Rollout',
		description:
			'New feature code paths lack feature flag or toggle controls, meaning all users are immediately exposed to new code upon deployment. ' +
			'CC3.4 risk assessment for changes should include staged rollout strategies; feature flags reduce blast radius and enable instant rollback without redeployment.',
		severity: 'low',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: cc3-017-missing-feature-flag
    patterns:
      - pattern: |
          if ($CONDITION) {
            $...BODY
          }
      - pattern-not: |
          if (featureFlag($FLAG)) {
            $...BODY
          }
      - pattern-not: |
          if (isEnabled($FLAG)) {
            $...BODY
          }
      - pattern-not: |
          if (flags.$FLAG) {
            $...BODY
          }
    message: >
      High-risk conditional code path without feature flag protection.
      Consider wrapping new features in a feature flag for controlled rollout.
    severity: INFO`,
			explanation:
				'Semgrep rule that identifies conditional branches adding significant new behavior that are not gated by a recognized feature flag pattern. Serves as an advisory to encourage feature flag adoption for risk mitigation.',
		},
		remediation:
			'Wrap high-risk or large new features behind a feature flag using a library such as LaunchDarkly, Unleash, or Flipt. ' +
			'Define a rollout plan: start at 1% of users, monitor error rates and business metrics, then progressively increase. ' +
			'Document the flag in the PR and set an expiry date to ensure cleanup.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc3-018',
		criteria: 'CC3.4',
		category: 'security',
		title: 'No Security-Focused Changelog or Release Notes for Risk Traceability',
		description:
			'The repository does not maintain a CHANGELOG or release notes file that records security-relevant changes, vulnerability fixes, or breaking changes. ' +
			'CC3.4 requires traceability of change risk; a security-focused changelog provides auditors with evidence that risks introduced by changes were identified and communicated.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'source'],
		pattern: {
			type: 'absence',
			value: '(CHANGELOG|CHANGES|RELEASE[_-]NOTES|HISTORY|NEWS)\\.(md|txt|rst|adoc)$',
			flags: 'i',
			explanation:
				'Checks for the absence of a CHANGELOG or equivalent release history file. Absence indicates no structured record of changes, security fixes, or risk-relevant modifications is maintained.',
		},
		remediation:
			'Create a CHANGELOG.md following the Keep a Changelog format (https://keepachangelog.com). ' +
			'Include a `### Security` section in every release entry to explicitly call out security fixes, CVE resolutions, and dependency updates. ' +
			'Automate changelog generation with tools like `git-cliff`, `conventional-changelog`, or `release-please`. ' +
			'Link each security entry to the corresponding CVE, issue, or PR for full traceability.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.iso.org/isoiec-27001-information-security.html',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},
];
