/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc8Rules: ISoc2Rule[] = [

	// ─── Infrastructure Changes (rules 001–008) ───────────────────────────────

	{
		id: 'cc8-001',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing Terraform plan review step in CI/CD pipeline',
		description:
			'The CI/CD pipeline applies Terraform changes (terraform apply) without a prior terraform plan step whose output is reviewed and approved, allowing unreviewed infrastructure mutations to reach production.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd', 'iac'],
		pattern: {
			type: 'regex',
			value: 'terraform\\s+apply(?![\\s\\S]{0,500}terraform\\s+plan)',
			flags: 'i',
			explanation:
				'Matches pipeline steps that run terraform apply without an earlier terraform plan step, indicating the plan output was never reviewed.',
		},
		remediation:
			'Split the pipeline into a plan stage that saves the plan file as an artifact and an apply stage that consumes that artifact after a human approval gate. Store plan outputs in a versioned artifact store for audit.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-002',
		criteria: 'CC8.1',
		category: 'security',
		title: 'No change approval gate before infrastructure deployment',
		description:
			'Infrastructure deployment pipelines proceed directly from a code merge to a live apply without any manual or automated approval gate, allowing unapproved changes to be applied automatically.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:approval|approvals|manual-approval|gates|reviewers|environment.*protection|waitForApproval|require_approval)',
			flags: 'i',
			explanation:
				'Flags CI/CD pipeline definitions that contain no approval gate, manual step, or environment protection rule before applying infrastructure changes.',
		},
		remediation:
			'Add a required manual approval step (e.g., GitHub Environments with required reviewers, Atlantis plan/apply workflow, or an ITSM change-ticket gate) before any terraform apply or equivalent command executes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-003',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing rollback mechanism in infrastructure pipeline',
		description:
			'The infrastructure deployment pipeline has no rollback step or documented rollback procedure, meaning a failed change leaves infrastructure in a partially modified state with no automated recovery path.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'iac'],
		pattern: {
			type: 'absence',
			value: '(?:rollback|roll_back|destroy|terraform\\s+state\\s+rm|restore_snapshot|previous_state|revert)',
			flags: 'i',
			explanation:
				'Flags infrastructure pipeline definitions that do not contain any rollback, revert, or state-restore step.',
		},
		remediation:
			'Define a rollback job or runbook that restores the previous Terraform state file or re-applies the previous known-good plan. Automate rollback on pipeline failure and test it in non-production regularly.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-004',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Unversioned infrastructure code (no VCS tracking)',
		description:
			'Infrastructure-as-code files are applied directly from a local working directory or shared network path rather than from a version-controlled repository, preventing change history, peer review, and rollback.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'iac'],
		pattern: {
			type: 'regex',
			value: 'terraform\\s+apply\\s+(?:\\.\\.|/tmp/|C:\\\\|/home/|/root/|/Users/)',
			flags: 'i',
			explanation:
				'Detects terraform apply commands that reference local file-system paths rather than a checked-out VCS workspace.',
		},
		remediation:
			'Store all IaC in a Git repository. Pipelines must check out the repository at a specific commit SHA before applying changes. Enforce branch protection and require pull-request review before merging to the deployment branch.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-005',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing change window enforcement for production deployments',
		description:
			'Production infrastructure changes can be applied at any time without restriction, including outside of approved maintenance windows, increasing the risk of unplanned outages and reducing incident response readiness.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:change.window|maintenance.window|deployment.window|schedule|cron.*deploy|freeze|blackout)',
			flags: 'i',
			explanation:
				'Flags production deployment pipeline definitions that contain no scheduling constraint, maintenance window check, or deployment freeze logic.',
		},
		remediation:
			'Configure deployment pipelines to enforce approved change windows (e.g., weekdays 10:00-16:00 UTC). Use GitHub Actions schedule triggers or deployment freeze rules. Require emergency change tickets for out-of-window deployments.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-006',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Terraform state stored locally without locking',
		description:
			'The Terraform backend is configured to store state locally or in a remote location without state locking, allowing concurrent applies that can corrupt the state file and cause unpredictable infrastructure drift.',
		severity: 'high',
		languages: ['any'],
		targets: ['iac'],
		pattern: {
			type: 'regex',
			value: 'backend\\s+"local"',
			flags: 'i',
			explanation:
				'Matches Terraform backend configurations using the local backend, which has no state locking and is unsuitable for team or automated workflows.',
		},
		remediation:
			'Migrate the Terraform state to a remote backend with locking support (e.g., S3 + DynamoDB, Terraform Cloud, Azure Blob with state locking, or GCS). Enable state encryption at rest.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-007',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Infrastructure changes applied with -auto-approve flag',
		description:
			'Terraform or OpenTofu is invoked with the -auto-approve flag, bypassing the interactive confirmation prompt and allowing changes to be applied without human acknowledgement of the plan diff.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'iac'],
		pattern: {
			type: 'regex',
			value: 'terraform\\s+apply\\s+.*-auto-approve',
			flags: 'i',
			explanation:
				'Detects terraform apply commands that include -auto-approve, which skips the plan review prompt.',
		},
		remediation:
			'Remove -auto-approve from all production pipeline commands. Use a saved plan file (terraform plan -out=plan.tfplan && terraform apply plan.tfplan) approved in a prior step instead of auto-approve.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-008',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing drift detection for infrastructure resources',
		description:
			'The pipeline or scheduled jobs do not run terraform plan in check-only mode to detect configuration drift between the desired state and the actual infrastructure, allowing undetected manual changes to persist.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'iac'],
		pattern: {
			type: 'absence',
			value: '(?:drift.detect|terraform\\s+plan.*-detailed-exitcode|driftctl|infracost.*drift|config-drift)',
			flags: 'i',
			explanation:
				'Flags IaC pipelines that do not include a drift detection step using terraform plan with -detailed-exitcode or a dedicated drift detection tool.',
		},
		remediation:
			'Add a scheduled pipeline job that runs terraform plan -detailed-exitcode and alerts the team when drift is detected. Treat detected drift as a change requiring review and re-apply.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	// ─── Code Changes (rules 009–016) ─────────────────────────────────────────

	{
		id: 'cc8-009',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing code review requirements in pipeline configuration',
		description:
			'The repository or pipeline configuration does not enforce a minimum number of approving code reviews before merging, allowing unreviewed code to reach production.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:required_approving_review_count|minApprovals|required-reviewers|min.reviewers|CODEOWNERS|pull.request.review)',
			flags: 'i',
			explanation:
				'Flags pipeline or repository configuration files that contain no reference to required reviewers or minimum approval counts.',
		},
		remediation:
			'Enable branch protection rules requiring at least two approving reviews. Configure a CODEOWNERS file so changes to sensitive directories trigger mandatory review from the owning team.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc8-010',
		criteria: 'CC8.1',
		category: 'security',
		title: 'No branch protection rules configured',
		description:
			'The default or production branch has no branch protection rules, allowing direct force-pushes, deletions, and merges without review or status checks.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: '(?:branch.protection|protected.branch|enforce_admins|restrictions|required_status_checks|dismiss_stale_reviews)',
			flags: 'i',
			explanation:
				'Flags repository configuration files that contain no branch protection settings for the main or default branch.',
		},
		remediation:
			'Enable branch protection on main/master: require pull requests, require status checks to pass, disallow force-pushes, and enforce rules for administrators. Use rulesets for GitHub repositories.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-011',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Direct commit to main or master branch detected',
		description:
			'A commit is pushed directly to the main or master branch rather than through a pull request, bypassing code review, status checks, and the change management process.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'regex',
			value: '(?:push\\s+.*(?:main|master)|on\\s*:\\s*push\\s*:\\s*branches\\s*:\\s*-\\s*(?:main|master))',
			flags: 'i',
			explanation:
				'Matches CI pipeline triggers or git push commands that directly target main or master, indicating direct push capability is enabled.',
		},
		remediation:
			'Block direct pushes to main/master via branch protection rules. Require all changes to go through a pull request with at least one approving review and all required status checks passing.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-012',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing signed commits requirement',
		description:
			'The repository does not require cryptographically signed commits, making it impossible to verify that commits were authored by the claimed developer and enabling commit attribution spoofing.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value: '(?:require_signed_commits|gpg.sign|commit.gpgsign|signingkey|sign-commits|signed.commits)',
			flags: 'i',
			explanation:
				'Flags repository configuration and pipeline definitions that contain no reference to commit signing requirements.',
		},
		remediation:
			'Enable "Require signed commits" in branch protection rules. Mandate GPG or SSH commit signing for all contributors. Verify commit signatures in CI via git log --show-signature.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-013',
		criteria: 'CC8.1',
		category: 'security',
		title: 'No required status checks before merge',
		description:
			'Branch protection rules do not require CI status checks (build, test, lint, security scan) to pass before merging, allowing broken or insecure code to be merged into the default branch.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value: '(?:required_status_checks|status-checks|required.checks|statusChecks|contexts.*required)',
			flags: 'i',
			explanation:
				'Flags repository configuration files that do not mandate required status checks as a merge prerequisite.',
		},
		remediation:
			'Configure branch protection to require at minimum: build pass, unit tests pass, and security scan (SAST/SCA) pass before any pull request can be merged. Mark required checks as strict.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc8-014',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Stale review approvals not dismissed on new commits',
		description:
			'Branch protection does not dismiss existing review approvals when new commits are pushed to a pull request, allowing a previously approved PR to be merged after the reviewed code has been modified.',
		severity: 'high',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: '(?:dismiss_stale_reviews|dismissStaleReviews|stale.review|stale-review)',
			flags: 'i',
			explanation:
				'Flags branch protection configurations that do not enable dismissal of stale reviews when new commits are pushed.',
		},
		remediation:
			'Enable "Dismiss stale pull request approvals when new commits are pushed" in branch protection rules. Pair this with a minimum of two required reviewers.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-015',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing CODEOWNERS file for sensitive directories',
		description:
			'The repository has no CODEOWNERS file, meaning changes to security-sensitive directories (auth, iac, config, secrets) do not automatically require review from designated owners.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: '(?:CODEOWNERS|codeowners)',
			flags: 'i',
			explanation:
				'Flags repositories or pipeline configurations that contain no reference to a CODEOWNERS file.',
		},
		remediation:
			'Create a .github/CODEOWNERS file that maps security-sensitive paths to the security team or senior engineers. Enable "Require review from Code Owners" in branch protection.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-016',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Self-approval of pull requests permitted',
		description:
			'The branch protection configuration does not prevent pull request authors from approving their own changes, undermining the segregation-of-duties requirement for code review.',
		severity: 'high',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: '(?:require_code_owner_reviews|dismiss_stale_reviews|restrict_dismissals|allow_self_approval.*false|require.*different.*reviewer)',
			flags: 'i',
			explanation:
				'Flags repository configurations that do not explicitly prevent authors from reviewing or approving their own pull requests.',
		},
		remediation:
			'Enable "Require a pull request before merging" and disable self-review. Require at least one review from a team member who is not the PR author. Use "Restrict who can dismiss pull request reviews" to prevent circumvention.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	// ─── Database Changes (rules 017–023) ─────────────────────────────────────

	{
		id: 'cc8-017',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing rollback script in database migration file',
		description:
			'A database migration file defines only the forward (up) migration without a corresponding rollback (down) migration, making it impossible to revert the schema change if an issue is discovered post-deployment.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'ruby', 'go', 'php'],
		targets: ['migration'],
		pattern: {
			type: 'absence',
			value: '(?:down|rollback|revert|undo|async\\s+down|exports\\.down|def\\s+down|func.*Down)',
			flags: 'i',
			explanation:
				'Flags migration files that contain an up/forward migration function but no corresponding down/rollback function.',
		},
		remediation:
			'Every migration file must include a rollback (down) function that precisely reverses the forward migration. Test rollbacks in CI by running up then down on a clean database schema.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-018',
		criteria: 'CC8.1',
		category: 'security',
		title: 'No migration testing step in CI pipeline',
		description:
			'The CI pipeline does not run database migrations against a test database before deploying, allowing untested schema changes to cause outages in staging or production.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:migrate.*test|test.*migrate|db.*migrate|run.*migration|migration.*ci|migrate.*up)',
			flags: 'i',
			explanation:
				'Flags CI pipeline definitions that contain no step to run or validate database migrations in a test environment.',
		},
		remediation:
			'Add a CI step that spins up a test database, applies all pending migrations, and runs the full test suite. Optionally run migrations up and then down to verify rollback correctness.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc8-019',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Destructive migration (DROP TABLE/COLUMN) without safety guard',
		description:
			'A database migration contains a DROP TABLE or DROP COLUMN statement without a preceding data backup step, a feature-flag check, or a multi-step deprecation process, risking unrecoverable data loss.',
		severity: 'critical',
		languages: ['any'],
		targets: ['migration', 'schema'],
		pattern: {
			type: 'regex',
			value: '\\b(?:DROP\\s+TABLE|DROP\\s+COLUMN|DROP\\s+DATABASE|TRUNCATE\\s+TABLE)\\b',
			flags: 'i',
			explanation:
				'Matches SQL DDL statements that permanently destroy tables, columns, or data without any surrounding safety mechanism.',
		},
		remediation:
			'Follow a multi-step deprecation: (1) stop writing to the column/table, (2) deploy for one full release cycle, (3) back up the data, (4) drop with an IF EXISTS guard. Never drop in the same migration that stops usage.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-020',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing database change approval in pipeline',
		description:
			'Database migration pipelines execute schema changes in production without a dedicated approval step, allowing unapproved DDL changes to be applied automatically.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:db.approval|database.approval|migration.approval|schema.approval|dba.review|dba-approval)',
			flags: 'i',
			explanation:
				'Flags database migration pipeline definitions that contain no DBA or database change approval gate.',
		},
		remediation:
			'Add a dedicated approval gate in the migration pipeline that requires sign-off from a DBA or database change advisory board (CAB) before applying schema changes to production.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc8-021',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Schema change executed without preceding database backup',
		description:
			'A migration pipeline applies schema changes to production without triggering a database snapshot or backup, leaving no recovery point if the migration causes data loss or corruption.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd', 'migration'],
		pattern: {
			type: 'absence',
			value: '(?:backup|snapshot|pg_dump|mysqldump|rds.*snapshot|db.backup|create.snapshot)',
			flags: 'i',
			explanation:
				'Flags migration pipeline definitions that execute database changes without a prior backup or snapshot step.',
		},
		remediation:
			'Take an automated database snapshot before applying any production migration. Verify the snapshot is complete before proceeding. Retain the pre-migration snapshot for at least 30 days.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-022',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Migration adds NOT NULL column without default value',
		description:
			'A migration adds a NOT NULL column to a table that already contains data without specifying a default value, which will fail on databases with existing rows or cause a full-table lock.',
		severity: 'high',
		languages: ['any'],
		targets: ['migration', 'schema'],
		pattern: {
			type: 'regex',
			value: 'ADD\\s+COLUMN\\s+\\w+[^;\\n]*NOT\\s+NULL(?![^;\\n]*DEFAULT)',
			flags: 'i',
			explanation:
				'Matches ALTER TABLE ADD COLUMN statements that include NOT NULL but omit a DEFAULT clause, which can break existing rows.',
		},
		remediation:
			'Use a multi-step process: (1) add the column as nullable, (2) backfill existing rows, (3) add the NOT NULL constraint in a separate migration once all rows have values.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-023',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing lock timeout on long-running schema migration',
		description:
			'An ALTER TABLE or index-creation migration does not set a lock timeout or use a safe concurrent option, risking prolonged table locks that can cause production downtime.',
		severity: 'high',
		languages: ['any'],
		targets: ['migration', 'schema'],
		pattern: {
			type: 'regex',
			value: '\\bALTER\\s+TABLE\\b(?![\\s\\S]{0,300}(?:lock_timeout|SET\\s+lock_timeout|CONCURRENTLY|NOWAIT))',
			flags: 'i',
			explanation:
				'Matches ALTER TABLE statements that do not include a lock_timeout setting or CONCURRENTLY option, indicating risk of long blocking locks.',
		},
		remediation:
			'Set a lock timeout before running ALTER TABLE in production (SET lock_timeout = \'2s\'). Use CREATE INDEX CONCURRENTLY and other non-blocking DDL patterns. Test migration lock duration in staging under production-like load.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	// ─── Deployment Changes (rules 024–030) ───────────────────────────────────

	{
		id: 'cc8-024',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing blue-green deployment configuration',
		description:
			'The deployment pipeline replaces the running application in-place rather than using a blue-green strategy, meaning any deployment failure immediately affects all production traffic with no instant rollback path.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'iac', 'kubernetes'],
		pattern: {
			type: 'absence',
			value: '(?:blue.green|blueGreen|blue_green|green.deployment|swap.slot|slot.swap|traffic.shift)',
			flags: 'i',
			explanation:
				'Flags deployment pipeline and infrastructure configurations that contain no blue-green, slot-swap, or equivalent zero-downtime deployment strategy.',
		},
		remediation:
			'Implement blue-green deployments using ECS service swap, Kubernetes rolling update with separate blue/green deployments, or AWS CodeDeploy blue-green. Route traffic only after health checks pass on the new environment.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-025',
		criteria: 'CC8.1',
		category: 'security',
		title: 'No canary deployment strategy configured',
		description:
			'The deployment pipeline sends 100% of traffic to the new version immediately, with no canary or incremental rollout strategy to limit blast radius during a faulty release.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'kubernetes', 'iac'],
		pattern: {
			type: 'absence',
			value: '(?:canary|canaryDeployment|canary.weight|trafficSplit|traffic.split|progressive.delivery|flagger|argo-rollout|rollout.weight)',
			flags: 'i',
			explanation:
				'Flags deployment definitions that contain no canary weight, traffic split, or progressive delivery configuration.',
		},
		remediation:
			'Implement canary deployments using Argo Rollouts, Flagger, or a service-mesh traffic split. Start at 5-10% traffic, monitor error rates and latency, and automate promotion or rollback based on metrics.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-026',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing deployment gate (health check validation)',
		description:
			'The deployment pipeline does not include a post-deployment health check gate that verifies the new version is healthy before completing the deployment, risking traffic being served by an unhealthy instance.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:health.check|healthcheck|readiness.check|liveness.check|wait.healthy|deployment.gate|verify.deployment)',
			flags: 'i',
			explanation:
				'Flags deployment pipeline definitions that do not include a health check or readiness validation step after deploying the new version.',
		},
		remediation:
			'Add a post-deployment step that polls the /health endpoint of the new deployment. Only mark the deployment successful and proceed with traffic routing after N consecutive successful health checks.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-027',
		criteria: 'CC8.1',
		category: 'security',
		title: 'No smoke tests in deployment pipeline',
		description:
			'The deployment pipeline completes without running any smoke tests against the newly deployed version, leaving undetected functional regressions that could affect production users.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:smoke.test|smoketest|smoke_test|post.deploy.*test|post-deploy.*test|sanity.check)',
			flags: 'i',
			explanation:
				'Flags deployment pipeline definitions that contain no smoke test or post-deployment functional validation step.',
		},
		remediation:
			'Add a smoke test stage after deployment that exercises the most critical user journeys (login, core workflow, health endpoint). Automatically trigger a rollback if any smoke test fails.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-028',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing environment parity check between staging and production',
		description:
			'The deployment pipeline does not validate that staging and production environments use the same configuration schema, dependency versions, or environment variable structure, increasing the risk of staging-only success.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:env.parity|environment.parity|config.diff|staging.match|env.diff|config.validation.*env)',
			flags: 'i',
			explanation:
				'Flags deployment configurations that do not include any comparison or validation of environment parity between staging and production.',
		},
		remediation:
			'Add a pre-deployment step that compares environment variable keys, Docker image tags, and dependency versions between staging and production. Fail the pipeline if critical discrepancies are detected.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-029',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Deployment pipeline missing automatic rollback on failure',
		description:
			'The deployment pipeline does not define an automatic rollback step that is triggered on deployment failure, requiring manual intervention and increasing mean time to recovery (MTTR).',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:on.failure.*rollback|rollback.on.failure|auto.rollback|automatic.rollback|rollbackOnFailure)',
			flags: 'i',
			explanation:
				'Flags deployment pipeline definitions that have no automatic rollback triggered by a deployment failure or failed health check.',
		},
		remediation:
			'Configure a pipeline failure handler that triggers rollback to the previous known-good version. Use Kubernetes rollout undo, ECS blue/green abort, or an equivalent mechanism. Test the rollback path in staging.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-030',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Container image deployed without vulnerability scan',
		description:
			'The deployment pipeline pushes or deploys container images without first scanning them for known vulnerabilities, allowing images with critical CVEs to reach production.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd', 'dockerfile'],
		pattern: {
			type: 'absence',
			value: '(?:trivy|snyk.*container|grype|clair|anchore|docker.scan|image.scan|vulnerability.scan)',
			flags: 'i',
			explanation:
				'Flags deployment pipelines that build or push container images without a container vulnerability scanning step.',
		},
		remediation:
			'Integrate a container scanner (Trivy, Snyk, Grype) into the CI pipeline as a required gate. Fail the build on critical or high CVEs. Rescan images on a schedule even after initial deployment.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	// ─── Testing Requirements (rules 031–035) ─────────────────────────────────

	{
		id: 'cc8-031',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing security tests (SAST/SCA) in CI pipeline',
		description:
			'The CI pipeline does not include Static Application Security Testing (SAST) or Software Composition Analysis (SCA) as a required gate, allowing code with known vulnerability patterns or vulnerable dependencies to be merged.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:semgrep|bandit|eslint.*security|gosec|brakeman|sonarqube|sonar|snyk|dependabot|sast|sca|codeql)',
			flags: 'i',
			explanation:
				'Flags CI pipeline definitions that contain no SAST or SCA tooling step.',
		},
		remediation:
			'Add SAST (e.g., CodeQL, Semgrep, Bandit) and SCA (e.g., Snyk, Dependabot, OWASP Dependency-Check) as required pipeline steps. Fail the merge queue on critical findings.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc8-032',
		criteria: 'CC8.1',
		category: 'security',
		title: 'No regression test requirement in change management process',
		description:
			'The pipeline and change management policy do not mandate regression tests for every change, allowing previously working functionality to be broken silently by new modifications.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:regression.test|regression_test|regression-test|full.test.suite|test.suite.*required)',
			flags: 'i',
			explanation:
				'Flags pipeline configurations that do not include a regression test execution step as a merge or deployment prerequisite.',
		},
		remediation:
			'Configure the CI pipeline to run the full regression test suite on every pull request. Block merges if any regression test fails. Track test failure trends in a dashboard.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-033',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing integration tests in CI/CD pipeline',
		description:
			'The pipeline only executes unit tests and does not run integration tests that verify cross-service or cross-component behavior, allowing integration failures to reach production undetected.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:integration.test|integration_test|integration-test|e2e.test|e2e_test|end.to.end)',
			flags: 'i',
			explanation:
				'Flags CI pipeline definitions that contain no integration or end-to-end test execution step.',
		},
		remediation:
			'Add an integration test stage that tests critical service interactions against a running environment. Consider contract testing (Pact) for microservice boundaries. Run end-to-end tests against a staging environment before production deployment.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-034',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Insufficient test coverage threshold enforcement',
		description:
			'The CI pipeline does not enforce a minimum code coverage threshold, allowing changes to ship with inadequate test coverage and increasing the risk of undetected defects in production.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:coverage.threshold|coverageThreshold|min.coverage|minimum.coverage|--coverage.*--passWithNoTests|coverage.*fail.*under|branches.*[6-9][0-9])',
			flags: 'i',
			explanation:
				'Flags pipeline and test configuration files that do not define or enforce a minimum code coverage percentage.',
		},
		remediation:
			'Configure Jest, pytest-cov, JaCoCo, or the relevant test framework to fail the build if coverage drops below an agreed threshold (e.g., 80% line coverage). Include branch, statement, and function coverage metrics.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-035',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing performance or load test before production deployment',
		description:
			'The deployment pipeline does not include a performance or load test stage, allowing capacity regressions or latency spikes introduced by new changes to go undetected until they impact production users.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: '(?:load.test|loadtest|load_test|performance.test|k6|locust|jmeter|gatling|artillery|stress.test)',
			flags: 'i',
			explanation:
				'Flags deployment pipeline definitions that contain no performance testing or load testing step before production deployment.',
		},
		remediation:
			'Add a load test stage (using k6, Locust, Gatling, or Artillery) that validates response times and error rates under expected peak traffic. Set failure thresholds aligned with SLOs and block deployment if exceeded.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc8-036',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Missing Branch Protection on Default Branch',
		description:
			'The repository configuration or CI/CD pipeline does not enforce branch protection rules on the default branch (main/master). Without branch protection, developers can push directly to the default branch, bypassing code review, required status checks, and the associated security gates.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value: '(?:branch.protection|required_pull_request_reviews|required_status_checks|CODEOWNERS|branch_protection)',
			flags: 'i',
			explanation:
				'Detects the absence of branch protection configuration in repository settings files or CI/CD workflow definitions. If no branch protection rules are referenced, direct pushes to the default branch may be permitted.',
		},
		remediation:
			'Enable branch protection on the default branch: require at least one approving review, require all status checks to pass before merging, disallow force pushes, and disallow deletion. Add a CODEOWNERS file so that security-sensitive paths require approval from security team members.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc8-037',
		criteria: 'CC8.1',
		category: 'security',
		title: 'Destructive Database Migration Without Explicit Down Migration',
		description:
			'A database migration file executes a destructive operation (DROP TABLE, DROP COLUMN, TRUNCATE) without providing a corresponding down-migration that can restore the removed schema. If the deployment fails after the migration runs, the database cannot be rolled back to its previous state.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['migration'],
		pattern: {
			type: 'regex',
			value: '(?:DROP\\s+TABLE|DROP\\s+COLUMN|TRUNCATE\\s+TABLE|dropTable|dropColumn|table\\.drop)(?![\\s\\S]{0,2000}(?:down|rollback|revert))',
			flags: 'i',
			explanation:
				'Matches destructive DDL statements or ORM migration helpers (dropTable, dropColumn) that are not followed within the same file by a down/rollback/revert function, indicating the migration is irreversible.',
		},
		remediation:
			'Pair every destructive migration statement with a corresponding down migration that recreates the dropped schema. For critical tables, consider a two-phase approach: first mark the column or table as deprecated and stop writing to it, then drop it in a follow-up migration only after confirming no active reads remain. Back up the database before running destructive migrations in production.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
];
