/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const pi1ErrorRules: ISoc2Rule[] = [

	// ─── PI1.4 Error Handling (rules 001–018) ─────────────────────────────────

	{
		id: 'pi1-err-001',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Swallowed exception in empty catch block',
		description:
			'A catch block is empty or contains only a comment, silently suppressing the exception. This prevents errors from being logged, investigated, or surfaced to operators, undermining processing integrity guarantees.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'catch\\s*\\([^)]*\\)\\s*\\{\\s*(?:\\/\\/[^\\n]*)?\\s*\\}',
			flags: 'gim',
			explanation:
				'Matches catch blocks whose body is empty or contains only whitespace and/or a single-line comment, indicating the exception is silently discarded.',
		},
		remediation:
			'Every catch block must at minimum log the error with sufficient context (operation name, correlation ID, error message, and stack trace) using the application\'s structured logger. Re-throw or propagate the error if the caller must be aware of the failure.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-err-002',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Missing error logging in catch block',
		description:
			'An exception is caught but not written to a structured log, making it impossible to detect recurring failures, perform post-incident root-cause analysis, or satisfy audit requirements for processing-integrity evidence.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:logger\\.|log\\.(?:error|warn|fatal)|console\\.error|logging\\.error|log\\.Error|Timber\\.|Rollbar\\.|Sentry\\.)',
			flags: 'i',
			explanation:
				'Flags catch blocks that do not contain any call to a logging function, indicating the error is consumed without being recorded.',
		},
		remediation:
			'Log every caught exception at the appropriate severity level (error or higher) using a structured logger. Include the error object, a human-readable message, a correlation or request ID, and the name of the failing operation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-003',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'No error classification or error-type taxonomy',
		description:
			'Errors are handled uniformly without distinguishing between transient (retryable), permanent, validation, or system-level failures. Without classification, the application cannot apply appropriate recovery strategies and operators cannot prioritise incidents effectively.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:ErrorCode|ErrorType|errorCode|error_code|error_type|isRetryable|isTransient|AppError|DomainError|ValidationError|SystemError)',
			flags: 'i',
			explanation:
				'Flags codebases whose error-handling paths contain no evidence of a structured error taxonomy or classification field, suggesting all errors are treated identically.',
		},
		remediation:
			'Define a typed error hierarchy or enum (e.g., ErrorCode, AppError subclasses) that distinguishes transient, permanent, validation, and system errors. Route each class to the appropriate handler (retry, alert, reject, rollback) based on its type.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-004',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Missing user-safe error message (internal detail exposed)',
		description:
			'Error responses sent to clients include raw exception messages, internal object representations, or other implementation details. Exposing internal error text violates the principle of least disclosure and may reveal exploitable system details.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'res\\.(?:json|send|status\\s*\\([^)]+\\)\\.json)\\s*\\([^)]*(?:err\\.message|error\\.message|e\\.message|exception\\.message)',
			flags: 'gi',
			explanation:
				'Matches response-sending calls that embed the raw error message object directly in the client response body, leaking internal error detail.',
		},
		remediation:
			'Map all errors to user-safe messages before sending them to clients. Log the original error server-side with a correlation ID. Return only the correlation ID and a generic, non-revealing message to the caller.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'pi1-err-005',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Stack trace included in API error response',
		description:
			'API error responses contain a stack trace, exposing file paths, line numbers, library versions, and internal call chains to external callers. This information materially aids attackers in targeting application vulnerabilities.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'res\\.(?:json|send|status\\s*\\([^)]+\\)\\.json)\\s*\\([^)]*(?:err\\.stack|error\\.stack|e\\.stack|stackTrace|stack_trace)',
			flags: 'gi',
			explanation:
				'Detects API response calls that include the error stack property, sending a full stack trace to the client.',
		},
		remediation:
			'Never include stack traces in API responses. Log the full stack trace server-side using a structured logger or error tracking service (Sentry, Rollbar). Return only a correlation ID and a generic error description to the client.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'pi1-err-006',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Missing error recovery procedure after caught exception',
		description:
			'After catching an exception, the code neither retries the operation, rolls back partial state, nor applies a compensating action. Leaving the system in an inconsistent intermediate state violates data and processing integrity requirements.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:rollback|compensate|recover|revert|undo|cleanup|cleanUp|abort|cancel|restore)',
			flags: 'i',
			explanation:
				'Flags catch blocks in transactional or multi-step operation code that perform no rollback, compensation, or recovery action, leaving state changes in an indeterminate condition.',
		},
		remediation:
			'Design error-handling paths to restore system state: roll back database transactions, undo partial file writes, release acquired locks, and emit a compensating event for distributed operations. Document the recovery procedure for each failure mode.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-007',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'No retry logic for transient errors',
		description:
			'Operations that call external services, message queues, or databases perform no retry on failure. A single transient network hiccup or temporary unavailability causes permanent data loss or silent processing failure, breaking processing integrity.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:retry|Retry|retryCount|retryAttempts|retry_count|attempt\\s*<|maxRetries|max_retries)',
			flags: 'i',
			explanation:
				'Flags external-service call sites in catch blocks or after awaited calls that contain no retry-count variable, loop, or retry-library usage, indicating transient failures are not retried.',
		},
		remediation:
			'Implement retry logic for all idempotent calls to external services. Use a battle-tested retry library (e.g., async-retry, tenacity, resilience4j) and limit the total number of attempts. Classify errors before retrying to avoid retrying permanent failures.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-008',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Missing exponential backoff on retry loop',
		description:
			'Retry logic retries at a fixed interval without exponential backoff or jitter. Fixed-interval retries can amplify load on a degraded dependency and delay recovery, causing cascading failures.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:exponential|backoff|Math\\.pow\\s*\\(|\\*\\s*2\\s*\\*\\s*attempt|delay\\s*\\*\\s*attempt|sleep\\s*\\(\\s*\\d+\\s*\\*\\s*(?:attempt|retry|i))',
			flags: 'i',
			explanation:
				'Flags retry loops or retry-library configurations that contain no exponential delay calculation (e.g., Math.pow, delay * attempt multiplier, or a backoff: "exponential" option).',
		},
		remediation:
			'Use exponential backoff with jitter for all retry delays: delay = min(cap, base * 2^attempt) + random_jitter. This spreads retry traffic and reduces thundering-herd load on recovering services.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-009',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'No timeout configured on external calls',
		description:
			'Calls to external HTTP APIs, databases, or message brokers have no timeout configured, causing the calling thread to block indefinitely if the remote service hangs. This can exhaust connection pools and produce undetected processing failures.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:timeout\\s*[=:,]|signal\\s*:\\s*AbortSignal|AbortController|socket_timeout|connect_timeout|read_timeout|requestTimeout|connectTimeout)',
			flags: 'i',
			explanation:
				'Flags HTTP client, database query, or external-service call sites that do not specify a timeout option or AbortSignal, leaving the request duration unbounded.',
		},
		remediation:
			'Set explicit connect and read timeouts on every external call. For fetch-based clients, pass an AbortSignal with a deadline. For database clients, set queryTimeout and connectionTimeout. Document the timeout rationale for each integration.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-010',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Missing fallback value or behaviour for failed dependency',
		description:
			'When a non-critical external dependency fails, the application propagates the failure rather than using a cached result, default value, or degraded-mode response. This causes cascading failures that compromise overall processing integrity.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:fallback|fallbackValue|defaultValue|cachedResult|degraded|gracefulDegrade|stale_while_revalidate|fallbackFn)',
			flags: 'i',
			explanation:
				'Flags external-dependency call sites in service or integration layers that define no fallback path, cached alternative, or degraded response for the failure scenario.',
		},
		remediation:
			'Identify non-critical dependencies and define a fallback strategy for each: return a cached value, a safe default, or a clearly degraded response. Implement the fallback using a circuit breaker or a try/catch with an explicit fallback path.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-011',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'No error rate alerting configured',
		description:
			'The application emits error logs but does not track error rates or configure threshold-based alerts. Without alerting, sustained elevated error rates go undetected until a customer reports a problem, violating proactive monitoring requirements under PI1.4.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:errorRate|error_rate|alerting|AlertManager|alertmanager|PagerDuty|pagerduty|OpsGenie|opsgenie|errorThreshold|error_threshold)',
			flags: 'i',
			explanation:
				'Flags application source code and configuration that records errors but contains no references to error-rate metrics emission, alerting thresholds, or on-call notification integrations.',
		},
		remediation:
			'Emit an error_rate metric on every exception handler. Configure a monitoring tool (Prometheus, Datadog, CloudWatch) to alert on-call engineers when the error rate exceeds a defined threshold (e.g., 1% of requests) for more than 5 minutes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-012',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Missing error budget tracking',
		description:
			'The application has no mechanism to track consumed error budget against a defined SLO. Without error budget awareness, engineering teams cannot make informed decisions about when to halt feature work and focus on reliability improvements.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:errorBudget|error_budget|slo|SLO|sloTarget|burnRate|burn_rate|errorBudgetRemaining)',
			flags: 'i',
			explanation:
				'Flags service-level code and configuration that contains no reference to SLO targets, error budget computation, or burn-rate metrics, indicating no formal reliability budget is being tracked.',
		},
		remediation:
			'Define error budget SLOs for all critical operations. Instrument error budget burn rate using a metrics platform. Alert when the burn rate indicates the error budget will be exhausted before the window ends and halt non-critical work accordingly.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-013',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'No circuit breaker on error threshold',
		description:
			'The application makes repeated calls to an external dependency that is in a failure state, without a circuit breaker to stop requests once the error threshold is exceeded. Continuous failed calls exhaust resources and delay overall recovery.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:CircuitBreaker|circuitBreaker|circuit_breaker|opossum|Hystrix|resilience4j|pybreaker|gobreaker|halfOpen|OPEN_STATE|CLOSED_STATE)',
			flags: 'i',
			explanation:
				'Flags external-integration or service-layer code that issues calls to downstream dependencies without any circuit breaker library usage or state-machine pattern, indicating no automatic failure isolation.',
		},
		remediation:
			'Wrap every external dependency call in a circuit breaker (e.g., opossum for Node.js, resilience4j for Java, pybreaker for Python). Configure open, half-open, and closed thresholds. Log state transitions and expose circuit state as a health metric.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-014',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Missing partial failure handling in batch operations',
		description:
			'Batch or bulk processing operations abort entirely on the first item failure rather than recording individual item errors and continuing. This prevents successfully processable items from completing, introducing data processing gaps.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:partialSuccess|partial_success|failedItems|failed_items|successCount|failureCount|processedCount|deadLetter|dead_letter)',
			flags: 'i',
			explanation:
				'Flags batch-processing loops and bulk-operation handlers that contain no per-item failure tracking, success/failure counters, or dead-letter queue routing, indicating all-or-nothing error semantics.',
		},
		remediation:
			'Implement per-item error handling in batch operations. Collect failed items into a dead-letter queue or error list. Report a partial-success result with counts of succeeded and failed items. Alert when the failure count exceeds an acceptable threshold.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-015',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'No idempotent retry guarantee (missing idempotency key)',
		description:
			'Operations that are retried on failure do not use an idempotency key or deduplication mechanism, meaning retried requests may be applied multiple times, resulting in duplicate records, double charges, or other data integrity violations.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:idempotencyKey|idempotency_key|Idempotency-Key|deduplicationId|deduplication_id|messageDeduplicationId)',
			flags: 'i',
			explanation:
				'Flags retry logic and write-operation code paths that contain no idempotency key generation, header, or deduplication ID, indicating retried operations are not protected against duplicate execution.',
		},
		remediation:
			'Generate a unique idempotency key per logical operation before the first attempt and include it on every retry. Implement server-side idempotency by storing the key and result and returning the cached result on duplicate requests within the idempotency window.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-err-016',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Missing error notification to affected stakeholders',
		description:
			'Critical processing errors are logged internally but no notification is sent to affected users, downstream systems, or operations teams. Without timely notification, impacted parties cannot take corrective action, prolonging data integrity exposure.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:sendNotification|notifyUser|notifyOps|notifyAdmin|sendAlert|emit\\s*\\(\\s*["\']error|publishEvent.*error|webhookNotify)',
			flags: 'i',
			explanation:
				'Flags critical or business-impacting error handlers that contain no notification dispatch (email, webhook, event publish, or push notification) to affected users or operators.',
		},
		remediation:
			'Classify errors by business impact. For errors that affect user data or SLA commitments, dispatch a notification to the affected user and the operations team. Include the error type, affected operation, timestamp, and remediation steps or ETA.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-017',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'No error persistence for post-incident analysis',
		description:
			'Errors are written only to ephemeral logs and not persisted to a queryable data store (database, error-tracking platform, or data warehouse). Without persistent error records, trends cannot be analysed, SLO reports cannot be generated, and audit evidence for PI1.4 cannot be produced.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:Sentry\\.captureException|Rollbar\\.error|Bugsnag\\.notify|errorRepository\\.save|ErrorLog\\.create|error_log\\.insert|persistError|storeError)',
			flags: 'i',
			explanation:
				'Flags error-handling code that relies solely on console or file logging with no call to a persistent error store or third-party error-tracking service, meaning errors are not queryable for trend analysis.',
		},
		remediation:
			'Integrate a persistent error tracking platform (Sentry, Rollbar, Bugsnag) or write structured error records to a queryable store (database, Elasticsearch). Ensure records include error type, message, stack trace, request context, and timestamp.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-err-018',
		criteria: 'PI1.4',
		category: 'integrity',
		title: 'Missing standardised error response format',
		description:
			'API error responses do not follow a consistent, documented structure (e.g., RFC 7807 Problem Details). Without a standard format, clients cannot reliably parse error codes and messages, leading to incorrect error handling, masked failures, and processing-integrity gaps in integrating systems.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:ProblemDetail|problem\\+json|application/problem|errorCode|error_code|correlationId|correlation_id|traceId|trace_id)',
			flags: 'i',
			explanation:
				'Flags API error-response construction code that does not reference a structured error format field (errorCode, traceId, correlationId) or RFC 7807 Problem Details content type, indicating ad-hoc unstructured error responses.',
		},
		remediation:
			'Adopt a standard API error response schema (RFC 7807 Problem Details or an equivalent). Include at minimum: a machine-readable error code, a human-readable message, a trace or correlation ID, and an HTTP status code. Document and version the error schema alongside the API contract.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

];
