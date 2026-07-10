/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const c1DisposalRules: ISoc2Rule[] = [
	{
		id: 'c1-disp-001',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'Missing Data Deletion API',
		description:
			'No explicit data deletion endpoint (DELETE /users, DELETE /records, etc.) is defined in the source code. ' +
			'Confidential data must be removable on request to satisfy C1.2 disposal requirements and regulatory mandates ' +
			'such as GDPR Article 17.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(router|app|route|@Delete|@RequestMapping|http\\.HandleFunc|delete_route|resources)\\s*[.(]\\s*[\'"`]?\\s*(DELETE|delete)',
			flags: 'i',
			explanation:
				'Checks for the absence of any HTTP DELETE route registration. If no DELETE handler is found in ' +
				'routing declarations the service lacks a data-deletion API surface.',
		},
		remediation:
			'Implement a DELETE endpoint (e.g., DELETE /api/v1/users/:id) that permanently removes or schedules ' +
			'removal of all confidential data associated with the resource. Return HTTP 204 on success and log ' +
			'the deletion event to the audit trail.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'c1-disp-002',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'No Soft Delete with Hard Delete Schedule',
		description:
			'Soft-deleted records (deleted_at, is_deleted) are present in the schema or codebase without any ' +
			'corresponding scheduled job or background worker that performs a physical (hard) delete after the ' +
			'retention window. Indefinitely retained soft-deleted confidential data violates C1.2 disposal obligations.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'schema', 'migration'],
		pattern: {
			type: 'regex',
			value:
				'deleted_at|is_deleted|soft.?delet|paranoid\\s*:\\s*true|SoftDeletableEntity|withDeleted\\(|onlyTrashed\\(|only_trashed',
			flags: 'i',
			explanation:
				'Detects soft-delete patterns in ORM configurations, column names, and query helpers. When found, ' +
				'the scanner checks whether a corresponding purge/hard-delete job is also defined in the same repository.',
		},
		remediation:
			'Pair every soft-delete mechanism with a scheduled purge job (cron, background worker, or database ' +
			'event) that hard-deletes rows whose deleted_at timestamp exceeds the defined retention period. ' +
			'Document the retention period in the data-classification register.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'c1-disp-003',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'Missing GDPR Right-to-Erasure Implementation',
		description:
			'No code path handles the GDPR "right to erasure" (Article 17) request lifecycle — including identity ' +
			'verification, cross-system propagation, and confirmation to the data subject. Processing personal data ' +
			'without an erasure path is a critical compliance gap under C1.2.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(rightToErasure|right_to_erasure|erasureRequest|erasure_request|handleErasure|handle_erasure|processErasure|process_erasure|forgetUser|forget_user|gdprDelete|gdpr_delete)',
			flags: 'i',
			explanation:
				'Searches for function or method names associated with GDPR erasure request handling. Absence of any ' +
				'such identifier in the source tree indicates no dedicated erasure flow exists.',
		},
		remediation:
			'Implement a GDPR erasure request handler that: (1) verifies the identity of the requester, ' +
			'(2) enqueues deletion tasks across all systems of record, (3) notifies downstream processors, ' +
			'(4) confirms completion to the data subject within 30 days, and (5) writes an audit record.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'c1-disp-004',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'No Data Retention Enforcement',
		description:
			'Data retention policies are not programmatically enforced. Without enforcement logic (TTL settings, ' +
			'expiry columns, retention-policy checks in write paths) confidential data accumulates indefinitely, ' +
			'creating unnecessary exposure and violating C1.2 disposal requirements.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config', 'schema'],
		pattern: {
			type: 'absence',
			value:
				'(retentionPolicy|retention_policy|retentionDays|retention_days|expiresAt|expires_at|ttl\\s*:|TTL\\s*=|data.?retention|purgeAfter|purge_after)',
			flags: 'i',
			explanation:
				'Detects the absence of retention-policy identifiers anywhere in the codebase, configuration, or schema. ' +
				'No TTL, expiry, or retention-day setting indicates data is kept indefinitely.',
		},
		remediation:
			'Define a retention policy per data class (e.g., 90 days for logs, 7 years for financial records). ' +
			'Enforce it by adding an expires_at column to sensitive tables, setting TTL in caches and message ' +
			'queues, and running a nightly purge job that deletes records past their retention date.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'c1-disp-005',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'Missing Backup Data Deletion',
		description:
			'When records are deleted from the primary store, backups and snapshots that contain those records are ' +
			'not invalidated or scheduled for re-encryption/deletion. Confidential data removed from production ' +
			'may still be recoverable from backup archives, violating C1.2 disposal completeness.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'any'],
		targets: ['source', 'config', 'iac'],
		pattern: {
			type: 'absence',
			value:
				'(deleteBackup|delete_backup|purgeBackup|purge_backup|backupRetention|backup_retention|snapshotExpiry|snapshot_expiry|backup.?lifecycle|BackupPolicy)',
			flags: 'i',
			explanation:
				'Searches for backup-deletion or backup-lifecycle management identifiers. Their absence suggests ' +
				'that deletion workflows do not extend to backup stores.',
		},
		remediation:
			'Extend the deletion workflow to: (1) tag affected backup snapshots for deletion or re-encryption, ' +
			'(2) configure backup lifecycle policies (e.g., AWS Backup, Azure Backup Policy) with a maximum ' +
			'retention window aligned to your data-retention register, and (3) document that backup purge ' +
			'has occurred in the deletion audit record.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'c1-disp-006',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'No Log Data Purging',
		description:
			'Application and access logs may contain confidential data (PII, tokens, query parameters) and no ' +
			'log-rotation or log-purge mechanism is configured. Indefinitely retained logs are a secondary ' +
			'data store subject to C1.2 disposal obligations.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'iac', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'(logRetention|log_retention|retentionInDays|retention_in_days|logPurge|log_purge|rotate.*log|log.*rotate|maxAge.*log|log.*maxAge)',
			flags: 'i',
			explanation:
				'Looks for log-rotation or log-retention configuration identifiers across config and IaC files. ' +
				'Absence suggests logs are written indefinitely without purging.',
		},
		remediation:
			'Configure log retention policies in your logging infrastructure (CloudWatch Logs retention, ' +
			'Elasticsearch ILM policy, logrotate config, etc.) to automatically delete or archive logs ' +
			'after the defined retention period. Scrub or mask confidential fields before writing to logs.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'c1-disp-007',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'Missing Cache Invalidation on Deletion',
		description:
			'When a record is deleted from the primary datastore, the corresponding in-process or distributed ' +
			'cache entry is not evicted. Stale cache entries can serve confidential data after it has been ' +
			'logically deleted, circumventing C1.2 disposal controls.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: c1-disp-007-cache-invalidation
    patterns:
      - pattern: |
          $REPO.delete(...)
      - pattern-not: |
          $CACHE.del(...)
      - pattern-not: |
          $CACHE.invalidate(...)
      - pattern-not: |
          $CACHE.evict(...)
    message: Record deletion without corresponding cache invalidation detected.
    languages: [typescript, javascript, python, java, go]
    severity: WARNING`,
			explanation:
				'Semgrep rule that matches delete calls on repository/DAO objects that are not followed by a ' +
				'corresponding cache eviction call in the same scope.',
		},
		remediation:
			'After every successful delete operation, evict the corresponding cache key(s) using ' +
			'cache.del(key), cache.invalidate(key), or an equivalent method. Use a cache-aside pattern ' +
			'or a repository decorator that automatically coordinates deletion with cache eviction.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},
	{
		id: 'c1-disp-008',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'No CDN Cache Purging on Data Deletion',
		description:
			'CDN-level caching of API responses or static assets is configured but no CDN cache-purge call is ' +
			'issued when confidential records are deleted. Cached CDN responses may expose confidential data ' +
			'for the full cache TTL after deletion, violating C1.2.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(cdnPurge|cdn_purge|purgeCache|purge_cache|cfPurge|cf_purge|cloudfront.*invalidat|fastly.*purge|akamai.*purge|cdn.*invalidat)',
			flags: 'i',
			explanation:
				'Searches for CDN cache-purge API call identifiers. Their absence alongside CDN configuration ' +
				'indicates that deletions do not propagate to the CDN edge.',
		},
		remediation:
			'Integrate a CDN cache-purge step into the deletion workflow. For CloudFront use ' +
			'CreateInvalidation; for Fastly use the Purge API; for Cloudflare use the Cache Purge API. ' +
			'Trigger the purge with the specific path(s) affected by the deleted record.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'c1-disp-009',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'Missing Data Export Before Deletion',
		description:
			'The deletion workflow does not offer or enforce a data-export step prior to permanent removal. ' +
			'Regulatory frameworks (GDPR Article 20, CCPA) grant data subjects the right to data portability ' +
			'before erasure; omitting this step creates a compliance gap under C1.2.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(exportData|export_data|dataExport|data_export|downloadData|download_data|portabilityExport|portability_export|generateExport|generate_export)',
			flags: 'i',
			explanation:
				'Searches for data-export or data-portability function identifiers. Their absence indicates no ' +
				'export step is offered before account or record deletion.',
		},
		remediation:
			'Implement a data-export endpoint that packages all data associated with a user or record into a ' +
			'portable format (JSON, CSV, ZIP) and delivers it securely before the deletion workflow completes. ' +
			'Provide the export URL in the deletion-confirmation communication.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'c1-disp-010',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'No Deletion Audit Trail',
		description:
			'Delete operations on confidential records do not write an audit-log entry recording who deleted ' +
			'the record, when, from which IP, and whether deletion was user-initiated or system-initiated. ' +
			'C1.2 requires demonstrable evidence of disposal actions.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: c1-disp-010-deletion-audit
    patterns:
      - pattern-either:
          - pattern: $REPO.delete(...)
          - pattern: $REPO.remove(...)
          - pattern: $REPO.destroy(...)
      - pattern-not-inside: |
          auditLog(...)
      - pattern-not-inside: |
          audit.log(...)
      - pattern-not-inside: |
          logger.audit(...)
    message: Deletion operation without audit log entry detected.
    languages: [typescript, javascript, python, java, go]
    severity: ERROR`,
			explanation:
				'Semgrep rule that matches repository delete/remove/destroy calls that are not wrapped or ' +
				'immediately followed by an audit-log write.',
		},
		remediation:
			'Wrap every delete operation in a service-layer method that: (1) performs the deletion, ' +
			'(2) writes an audit record to an append-only audit log containing actor, timestamp, ' +
			'IP address, resource type, resource ID, and deletion reason. Use a transactional outbox ' +
			'pattern to guarantee the audit entry is written even if the primary transaction rolls back.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'c1-disp-011',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'Missing Cascading Delete Verification',
		description:
			'Database migrations or ORM models define foreign-key relationships without ON DELETE CASCADE or ' +
			'equivalent application-level cascading logic. Deleting a parent record leaves orphaned child ' +
			'records containing confidential data, resulting in incomplete disposal under C1.2.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['migration', 'schema', 'source'],
		pattern: {
			type: 'regex',
			value:
				'REFERENCES\\s+\\w+\\s*\\([^)]+\\)(?!\\s*ON\\s+DELETE)|foreign.*key(?!.*cascade)|@OneToMany(?![^;]{0,200}cascade)|@ManyToMany(?![^;]{0,200}cascade)',
			flags: 'gi',
			explanation:
				'Detects REFERENCES clauses in SQL migrations that lack an ON DELETE directive, as well as JPA ' +
				'@OneToMany and @ManyToMany annotations missing a cascade parameter, indicating that child ' +
				'records will not be removed when the parent is deleted.',
		},
		remediation:
			'For each foreign key referencing a table that holds confidential data, add ON DELETE CASCADE ' +
			'(or ON DELETE SET NULL followed by a purge job) to the migration. In ORM models, set ' +
			'cascade: ["remove"] or equivalent. Add integration tests that verify child records are ' +
			'removed when the parent is deleted.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'c1-disp-012',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'No Third-Party Data Deletion Notification',
		description:
			'When confidential data is deleted, downstream third-party processors (analytics vendors, CRMs, ' +
			'email service providers) that hold a copy are not notified. Data shared with processors ' +
			'remains subject to C1.2 disposal obligations; failing to notify processors leaves an open ' +
			'disposal gap.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(notifyProcessor|notify_processor|processorDeletion|processor_deletion|thirdPartyDelete|third_party_delete|webhookDelete|webhook_delete|dataProcessorNotif)',
			flags: 'i',
			explanation:
				'Searches for third-party processor notification identifiers in the deletion workflow. Their ' +
				'absence indicates no mechanism exists to inform processors of deletion events.',
		},
		remediation:
			'Maintain a data-processor inventory. After a deletion event, enqueue notifications to each ' +
			'processor (via their deletion API, webhook, or support ticket) and record the notification ' +
			'in the audit trail. Implement a retry/dead-letter queue so failed notifications are retried ' +
			'and escalated.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'c1-disp-013',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'Missing Anonymization as Deletion Alternative',
		description:
			'For records where hard deletion would break referential integrity or statistical datasets, ' +
			'anonymization is an accepted disposal alternative under GDPR Recital 26. The absence of any ' +
			'anonymization function means records that should be anonymized are either deleted unsafely ' +
			'or retained in identifiable form, both of which violate C1.2.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(anonymize|anonymise|pseudonymize|pseudonymise|maskData|mask_data|scrubPII|scrub_pii|redactUser|redact_user|obfuscateUser|obfuscate_user)',
			flags: 'i',
			explanation:
				'Searches for anonymization or pseudonymization function identifiers. Their absence indicates ' +
				'no anonymization path exists as an alternative to hard deletion.',
		},
		remediation:
			'Implement an anonymization function that replaces PII fields (name, email, phone, address) ' +
			'with synthetic or hashed values while preserving the structural record for analytics. ' +
			'Invoke it as an alternative to deletion for records constrained by referential integrity, ' +
			'and log the anonymization event in the audit trail.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'c1-disp-014',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'No Deletion Confirmation Workflow',
		description:
			'Deletion requests are processed immediately without a confirmation step (e.g., email confirmation, ' +
			'MFA re-authentication, or a grace period with undo capability). Without confirmation, accidental ' +
			'or malicious deletion requests can irreversibly destroy data, and there is no evidence of ' +
			'intentional disposal as required by C1.2.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(confirmDelete|confirm_delete|deletionConfirm|deletion_confirm|pendingDeletion|pending_deletion|deletionGracePeriod|deletion_grace_period|scheduleDeletion|schedule_deletion)',
			flags: 'i',
			explanation:
				'Searches for deletion-confirmation or grace-period identifiers. Their absence indicates ' +
				'deletions are immediate with no confirmation or undo window.',
		},
		remediation:
			'Introduce a two-step deletion workflow: (1) the user requests deletion and receives a ' +
			'confirmation email or must pass MFA; (2) the record is placed in a pending_deletion state ' +
			'with a configurable grace period (e.g., 14 days); (3) after the grace period the record ' +
			'is permanently deleted. Allow cancellation during the grace period.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'c1-disp-015',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'Missing Irreversible Deletion Safeguards',
		description:
			'Hard-delete operations on confidential records can be executed by any authenticated user ' +
			'or automated process without additional authorization controls (e.g., separate admin role, ' +
			'dual-control approval, or deletion-specific permission scope). This allows accidental or ' +
			'unauthorized irreversible disposal, undermining C1.2 governance.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: c1-disp-015-irreversible-delete-guard
    patterns:
      - pattern-either:
          - pattern: $REPO.delete(...)
          - pattern: $REPO.hardDelete(...)
          - pattern: $REPO.permanentDelete(...)
      - pattern-not-inside: |
          requireRole(...)
      - pattern-not-inside: |
          authorize(...)
      - pattern-not-inside: |
          checkPermission(...)
    message: Irreversible delete without authorization check detected.
    languages: [typescript, javascript, python, java, go]
    severity: ERROR`,
			explanation:
				'Semgrep rule that flags hard-delete calls that are not guarded by a role-check or permission ' +
				'authorization call within the same function scope.',
		},
		remediation:
			'Gate all irreversible delete operations behind a dedicated permission scope (e.g., ' +
			'data:delete:permanent). Require MFA re-authentication or a manager approval step for bulk ' +
			'or administrative deletions. Log authorization decisions alongside the deletion audit record.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'c1-disp-016',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'No Deletion Scheduling Mechanism',
		description:
			'There is no scheduled or deferred deletion mechanism in the codebase (cron jobs, task queues, ' +
			'cloud scheduler invocations). Without scheduled deletion, retention policy enforcement depends ' +
			'entirely on manual intervention, which is unreliable and fails C1.2 systematic disposal requirements.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'any'],
		targets: ['source', 'config', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'(cron|CronJob|schedule.*delet|delet.*schedule|scheduledTask|scheduled_task|TaskScheduler|@Scheduled|celery.*beat|sidekiq.*scheduler|backgroundJob|background_job)',
			flags: 'i',
			explanation:
				'Searches for scheduled-task or cron-job identifiers related to deletion. Their absence ' +
				'indicates no automated deletion schedule is implemented.',
		},
		remediation:
			'Implement a scheduled deletion job (using cron, AWS EventBridge + Lambda, Celery Beat, ' +
			'Sidekiq Scheduler, or equivalent) that runs on a defined interval to purge records past ' +
			'their retention date. Monitor job execution and alert on failures to ensure the schedule ' +
			'is reliably enforced.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'c1-disp-017',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'Missing Deletion Verification',
		description:
			'After executing a deletion, no verification step confirms that the record has been removed ' +
			'from all relevant stores (primary DB, replicas, search indexes, caches). Without post-deletion ' +
			'verification the deletion completion claim in the audit trail may be inaccurate, violating ' +
			'C1.2 demonstrable disposal requirements.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(verifyDeletion|verify_deletion|confirmDeletion|confirm_deletion|assertDeleted|assert_deleted|deletionVerif|deletion_verif|postDeleteCheck|post_delete_check)',
			flags: 'i',
			explanation:
				'Searches for post-deletion verification function identifiers. Their absence suggests that ' +
				'deletions are assumed complete without cross-store confirmation.',
		},
		remediation:
			'After each deletion, perform a read-back check across all relevant stores (primary DB, ' +
			'read replicas, Elasticsearch, Redis, S3) to confirm the record is no longer accessible. ' +
			'Record the verification result in the audit log. Raise an alert if verification fails.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'c1-disp-018',
		criteria: 'C1.2',
		category: 'confidentiality',
		title: 'No Secure Overwrite of Sensitive Data',
		description:
			'Sensitive data stored in files, block storage, or memory buffers is deleted using standard ' +
			'OS unlink/free operations without cryptographic erasure or secure overwrite. On spinning ' +
			'disks, SSDs with wear-leveling, or block-storage snapshots, deleted data may remain ' +
			'recoverable. C1.2 requires that confidential data be rendered irretrievable upon disposal.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'c', 'cpp', 'csharp', 'rust'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(fs\\.unlinkSync|fs\\.unlink|os\\.remove|File\\.Delete|Files\\.delete|os\\.unlink|DeleteFile|remove\\s*\\(["\'].*\\.(pem|key|p12|pfx|csv|bak|dump))',
			flags: 'gi',
			explanation:
				'Detects standard file deletion calls (fs.unlink, os.remove, File.Delete) applied to ' +
				'files with sensitive extensions (PEM, key, p12, pfx, csv, bak, dump). These calls do ' +
				'not perform secure overwrite and the data may be recoverable from disk.',
		},
		remediation:
			'Replace standard file deletion with a secure-erase utility (e.g., shred, srm, or a ' +
			'cryptographic erasure approach where the file is encrypted with a one-time key that is ' +
			'then discarded before deletion). For cloud block storage, rely on AES-256 encryption at ' +
			'rest combined with key deletion to render data unrecoverable. For in-memory buffers, ' +
			'zero-fill the buffer before freeing (use SecureZeroMemory, explicit_bzero, or equivalent).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
];
