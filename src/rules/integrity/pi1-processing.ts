/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const pi1ProcessingRules: ISoc2Rule[] = [

	// ─── PI1.2 Processing Rules (rules 001–018) ───────────────────────────────

	{
		id: 'pi1-proc-001',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'Missing transaction atomicity in multi-step database operations',
		description:
			'Multiple related database write operations are executed sequentially without wrapping them in a single atomic transaction. A failure partway through leaves the database in a partially updated, inconsistent state that violates processing integrity.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:await\\s+\\w+\\.(?:save|create|update|delete|insert)\\s*\\([^)]*\\)\\s*;[\\s\\S]{0,300}await\\s+\\w+\\.(?:save|create|update|delete|insert)\\s*\\([^)]*\\))(?![\\s\\S]{0,500}(?:transaction|beginTransaction|startTransaction|withTransaction))',
			flags: 'i',
			explanation:
				'Detects two or more sequential async database mutation calls in close proximity that are not wrapped in a transaction block, indicating missing atomicity.',
		},
		remediation:
			'Wrap all related database writes in a single database transaction. Use ORM transaction helpers (e.g., sequelize.transaction(), prisma.$transaction(), knex.transaction()) or raw BEGIN/COMMIT blocks. Ensure the transaction is rolled back on any error.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'pi1-proc-002',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'No database transaction rollback on error',
		description:
			'A database transaction is started but error-handling code does not call rollback when an exception is thrown, leaving open transactions or partially applied changes that corrupt processing state.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:rollback|transaction\\.rollback|trx\\.rollback|conn\\.rollback|session\\.rollback|tx\\.Rollback)',
			flags: 'i',
			explanation:
				'Flags source files that contain transaction-begin calls but no corresponding rollback call, indicating error paths that silently omit transaction rollback.',
		},
		remediation:
			'Add explicit rollback calls in all catch/error branches of transaction-bearing code. Use try/catch/finally patterns to guarantee rollback is always called on failure: try { await trx.commit(); } catch { await trx.rollback(); throw; }.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-proc-003',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'Missing optimistic locking on concurrent record updates',
		description:
			'Update operations on shared records do not use a version field or timestamp-based optimistic lock. Concurrent writers can silently overwrite each other\'s changes, causing lost updates and data integrity violations.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source', 'schema'],
		pattern: {
			type: 'absence',
			value: '(?:version|versionKey|@Version|optimisticLock|optimistic_lock|row_version|etag|if-match|updatedAt.*where|WHERE.*version\\s*=)',
			flags: 'i',
			explanation:
				'Flags record-update code paths and schema definitions that contain no version column check, ETag header, or ORM optimistic-locking annotation.',
		},
		remediation:
			'Add a version integer column (or updatedAt timestamp) to records subject to concurrent modification. Include the expected version value in the WHERE clause of every UPDATE statement and reject updates where zero rows are affected. Use ORM optimistic-locking annotations (@Version in JPA, optimisticConcurrency in Prisma).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-proc-004',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'No idempotency key for stateful operations',
		description:
			'Operations that mutate state (payments, orders, transfers) do not accept or persist an idempotency key, so network retries or duplicate client submissions create duplicate records and double-processing.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:idempotency.?key|idempotencyKey|x-idempotency-key|idempotent_key|deduplication.?id)',
			flags: 'i',
			explanation:
				'Flags POST/mutation route handlers for payment, order, or transfer operations that do not check for or store an idempotency key.',
		},
		remediation:
			'Require clients to supply an Idempotency-Key header on all state-mutating requests. Persist the key alongside the result with an appropriate TTL (e.g., 24 hours). On repeated requests with the same key, return the cached result without re-executing the operation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-proc-005',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'Missing duplicate detection before record insertion',
		description:
			'Insert operations do not check for the prior existence of a logically equivalent record (same business key) before writing, enabling duplicate records that compromise processing integrity and reporting accuracy.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'migration', 'schema'],
		pattern: {
			type: 'absence',
			value: '(?:findOrCreate|upsert|insertOrIgnore|ON CONFLICT|on_conflict|UNIQUE\\s+CONSTRAINT|unique_together|duplicate.*check|isDuplicate|dedup)',
			flags: 'i',
			explanation:
				'Flags INSERT operations and schema definitions that contain no duplicate-detection guard, unique constraint, or upsert pattern.',
		},
		remediation:
			'Add a unique database constraint on the natural business key columns. Use INSERT ... ON CONFLICT DO NOTHING / upsert patterns in application code. Implement an application-level existence check inside the same transaction before inserting.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-proc-006',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'No concurrent modification protection on shared resource',
		description:
			'Code that reads, computes, and writes a shared resource (counter, balance, inventory) does not acquire a lock or use a compare-and-swap operation, creating a read-modify-write race condition that corrupts values under concurrent load.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:SELECT[\\s\\S]{0,200}UPDATE|findOne[\\s\\S]{0,300}\\.save\\s*\\(|get\\s*\\([^)]*\\)[\\s\\S]{0,200}set\\s*\\()(?![\\s\\S]{0,300}(?:FOR UPDATE|LOCK IN SHARE MODE|SELECT.*SKIP LOCKED|mutex|lock\\(|Lock\\(|synchronized|atomic|Atomic|compare_and_swap|CompareAndSwap|compareAndSet))',
			flags: 'i',
			explanation:
				'Detects read-then-write patterns on shared data that are not protected by a pessimistic lock, mutex, or atomic compare-and-swap operation.',
		},
		remediation:
			'Use SELECT ... FOR UPDATE to acquire a pessimistic row lock within a transaction, or use atomic database operations (UPDATE counter = counter + 1 WHERE id = ?). For in-memory shared state, use mutexes, semaphores, or language-provided atomic primitives.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'pi1-proc-007',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'Missing data consistency checks after processing',
		description:
			'Processing pipelines do not validate output data against expected invariants or checksums after execution, leaving silently corrupted results in downstream systems.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:consistencyCheck|sanityCheck|integrityCheck|checksum|hashVerif|invariant|assertBalanced|assertEqual|verifySum|reconcile)',
			flags: 'i',
			explanation:
				'Flags data processing pipeline functions that produce output but contain no post-processing consistency check, checksum verification, or invariant assertion.',
		},
		remediation:
			'Add post-processing validation steps that verify output totals, record counts, and checksums match expected values. Implement invariant checks (e.g., debits equal credits for financial data) and raise alerts on any discrepancy before committing results.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-proc-008',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'No referential integrity enforcement at the database level',
		description:
			'Foreign key relationships between tables are not enforced with database-level FOREIGN KEY constraints, allowing child records to reference non-existent parents and breaking relational consistency.',
		severity: 'high',
		languages: ['any'],
		targets: ['migration', 'schema'],
		pattern: {
			type: 'absence',
			value: '(?:FOREIGN KEY|REFERENCES|foreignKey|references|addForeignKey|createForeignKey|\.foreign\\()',
			flags: 'i',
			explanation:
				'Flags migration and schema files that create tables with apparent relationship columns (e.g., *_id suffix) but declare no FOREIGN KEY constraint enforcing referential integrity.',
		},
		remediation:
			'Declare explicit FOREIGN KEY constraints with appropriate ON DELETE / ON UPDATE actions in all migration files. Enable foreign key enforcement at the database level (e.g., PRAGMA foreign_keys = ON for SQLite). Do not rely solely on application-layer relationship validation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'pi1-proc-009',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'Missing cascade delete safeguards on parent record removal',
		description:
			'Deleting a parent record performs no cascade delete or nullification of dependent child records, causing orphaned rows that reference a now-deleted entity and corrupt query results.',
		severity: 'high',
		languages: ['any'],
		targets: ['migration', 'schema', 'source'],
		pattern: {
			type: 'regex',
			value: 'ON\\s+DELETE\\s+(?:NO\\s+ACTION|RESTRICT)(?![\\s\\S]{0,1000}(?:soft.?delete|paranoid|deleted_at|archivedAt))',
			flags: 'i',
			explanation:
				'Matches FOREIGN KEY definitions with ON DELETE NO ACTION or RESTRICT that are not accompanied by any soft-delete mechanism, leaving dependent records dangling after parent deletion.',
		},
		remediation:
			'Choose an explicit delete strategy: (a) ON DELETE CASCADE to remove child records automatically, (b) ON DELETE SET NULL when orphan nullification is acceptable, or (c) implement soft-delete (deleted_at column) with application-layer guards that prevent deletion while active children exist.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'pi1-proc-010',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'No orphaned record prevention in application logic',
		description:
			'Application code deletes or detaches parent entities without checking for or cleaning up dependent child records that have no enforcement mechanism at the database level, producing orphaned rows that pollute aggregates and reports.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:\.destroy\\s*\\(|\.delete\\s*\\(|DELETE FROM\\s+\\w+\\s+WHERE)(?![\\s\\S]{0,500}(?:cascade|deleteMany|destroyAll|dependent.*destroy|bulkDelete.*children|cleanup|cleanUp|removeChildren|deleteRelated))',
			flags: 'i',
			explanation:
				'Detects entity/record deletion calls that are not followed by child-cleanup logic and have no cascading ORM option configured.',
		},
		remediation:
			'Before deleting a parent record, enumerate and delete (or reassign) all dependent child records. Use ORM cascade options (dependent: :destroy in ActiveRecord, cascade: true in Sequelize) and verify they are correctly applied to all relationships.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-proc-011',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'Missing business rule validation before data persistence',
		description:
			'Data is persisted to the database without validating domain-specific business rules (e.g., balance cannot be negative, order quantity must be positive, start date must precede end date), allowing invalid application states to be stored.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:\.save\\s*\\(|\.create\\s*\\(|\.insert\\s*\\(|INSERT\\s+INTO)(?![\\s\\S]{0,800}(?:validate|validation|validator|isValid|checkRule|businessRule|invariant|guard|assert|verify))',
			flags: 'i',
			explanation:
				'Flags persistence calls that are not preceded by a domain validation or business-rule check within the same logical code block.',
		},
		remediation:
			'Implement a validation layer (service or domain object) that enforces all business rules before any persistence call. Add database CHECK constraints as a secondary enforcement layer. Return structured validation errors to callers rather than allowing invalid writes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-proc-012',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'No calculation audit trail for financial or aggregated computations',
		description:
			'Financial totals, aggregated metrics, or derived values are computed and stored without recording the input values and calculation steps, making it impossible to audit, reproduce, or dispute the results.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:calculationLog|calc_log|auditTrail|computationRecord|ledgerEntry|lineItem|breakdown|calculation_detail|audit_entry)',
			flags: 'i',
			explanation:
				'Flags financial or aggregate calculation functions that produce a result but emit no audit log record capturing the input operands and formula used.',
		},
		remediation:
			'Persist a calculation audit record alongside every derived value, capturing: input operands, formula or rule version applied, timestamp, and actor. Use an append-only audit table or event-sourcing approach so the record cannot be altered after the fact.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'pi1-proc-013',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'Missing processing order guarantees in batch jobs',
		description:
			'Batch processing jobs iterate over records without enforcing a deterministic order. Records that have sequential dependencies may be processed out of order, producing incorrect results when later steps depend on the output of earlier ones.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:ORDER BY|orderBy|sortBy|\.sort\\s*\\(|sequence_number|seq_num|processingOrder|batchOrder)',
			flags: 'i',
			explanation:
				'Flags batch processing loops and database result sets that are iterated without an explicit ORDER BY or sort operation, indicating no guaranteed processing sequence.',
		},
		remediation:
			'Add an explicit ORDER BY clause to all queries that feed batch jobs with sequential dependencies. Use sequence numbers or creation timestamps as sort keys. Document the required processing order and add an assertion that verifies ordering invariants at the start of each batch run.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-proc-014',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'No message ordering enforcement on message queue consumer',
		description:
			'A message queue consumer processes messages without enforcing ordered delivery within a partition or ordering key, allowing out-of-order processing of sequentially dependent events such as state transitions or financial adjustments.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:partitionKey|partition_key|orderingKey|ordering_key|messageGroupId|message_group_id|FIFO|sequenceToken|sequence_number)',
			flags: 'i',
			explanation:
				'Flags message queue consumer configuration and handler code that contains no partition key, ordering key, or FIFO queue designation to guarantee ordered delivery.',
		},
		remediation:
			'Use a message broker that supports ordered delivery (e.g., SQS FIFO queues, Kafka partitions, Google Cloud Tasks with ordering keys). Set the partitionKey or messageGroupId to the entity identifier so that all messages for a given entity are processed in order.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-proc-015',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'Missing exactly-once delivery semantics for critical operations',
		description:
			'Event-driven operations that must not be applied more than once (e.g., charge a payment, credit an account, send a legal notification) rely on at-least-once delivery without idempotency guards, risking duplicate side effects.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:exactly.?once|idempotent|deduplication|message_id.*seen|event_id.*processed|processedEvents|idempotencyTable|at_least_once.*guard)',
			flags: 'i',
			explanation:
				'Flags critical event handler code that performs irreversible side effects (payment, notification, ledger entry) but contains no deduplication check or exactly-once guard.',
		},
		remediation:
			'Implement an idempotency table that records processed message IDs. Before executing the side effect, check whether the message ID has already been processed within the same transaction. Use transactional outbox or saga patterns to coordinate exactly-once semantics across services.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},

	{
		id: 'pi1-proc-016',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'No poisoned message handling in queue consumer',
		description:
			'Message queue consumers do not detect or handle poisoned (malformed or repeatedly failing) messages. A single bad message blocks the queue, causing processing stalls and eventual data integrity failures for all subsequent messages.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: '(?:maxReceiveCount|max_receive_count|receiveCount|receive_count|poisonMessage|poison_message|maxDeliveryCount|max_delivery_count|deliveryCount|redeliveryPolicy)',
			flags: 'i',
			explanation:
				'Flags message consumer configuration and handler code that does not track delivery attempt counts or detect poisoned messages exceeding a retry threshold.',
		},
		remediation:
			'Configure a maximum receive count on all queues. After the threshold is exceeded, route the message to a dead-letter queue (DLQ) automatically. Log the failed message with its full context for manual investigation and alert on-call when messages land in the DLQ.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-proc-017',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'Missing dead letter queue configuration on message broker',
		description:
			'Message queues or topics are configured without a dead letter queue (DLQ) destination, causing unprocessable messages to be silently discarded or to block the queue indefinitely with no visibility into processing failures.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'absence',
			value: '(?:deadLetterQueue|dead_letter_queue|deadLetterTargetArn|dead_letter_target_arn|DeadLetterConfig|dlq|DLQ|redrive_policy|redrivePolicy)',
			flags: 'i',
			explanation:
				'Flags queue or topic resource definitions in IaC or configuration files that contain no dead-letter queue or redrive policy configuration.',
		},
		remediation:
			'Attach a DLQ to every SQS queue, SNS topic, EventBridge rule, or equivalent resource. Set a maxReceiveCount (typically 3–5). Configure CloudWatch alarms or equivalent monitoring to alert when messages arrive in the DLQ. Implement a DLQ replay mechanism for remediation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'pi1-proc-018',
		criteria: 'PI1.2',
		category: 'integrity',
		title: 'No partial failure recovery in distributed processing pipeline',
		description:
			'Distributed processing pipelines do not implement checkpoint, compensating transaction, or saga patterns. A mid-pipeline failure leaves some downstream systems updated and others not, producing permanently inconsistent data across services.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:checkpoint|compensat|saga|outbox|twoPhaseCommit|two_phase_commit|distributedTransaction|distributed_transaction|partialFailure|partial_failure|rollbackSaga|compensatingTransaction)',
			flags: 'i',
			explanation:
				'Flags distributed orchestration or pipeline code that calls multiple external services or performs cross-system writes but contains no checkpoint, compensation, or saga coordination logic.',
		},
		remediation:
			'Adopt the Saga pattern (choreography or orchestration) for distributed transactions. Implement compensating transactions for each step that can be rolled back. Use the transactional outbox pattern to guarantee event publication atomicity. Persist saga state so recovery can resume from the last successful checkpoint after a failure.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
			'https://www.nist.gov/cyberframework',
		],
	},
];
