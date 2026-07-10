/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const pi1AccuracyRules: ISoc2Rule[] = [
	{
		id: 'pi1-acc-001',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Floating-Point Arithmetic Used for Monetary Values',
		description:
			'Detects use of native floating-point types (float, double, number) in monetary calculations. IEEE 754 binary floating-point cannot represent many decimal fractions exactly, causing systematic rounding errors in financial computations. Processing integrity requires that monetary values remain accurate throughout all calculations.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'java', 'go', 'python', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:price|amount|total|balance|cost|fee|rate|tax|discount|subtotal|revenue|salary|wage|payment)\\s*[\\+\\-\\*\\/]\\s*(?:price|amount|total|balance|cost|fee|rate|tax|discount|subtotal|revenue|salary|wage|payment|\\d+\\.\\d+)',
			flags: 'gi',
			explanation:
				'Matches arithmetic operations on identifiers whose names imply monetary values, signalling potential float-based money math.',
		},
		remediation:
			'Replace native floating-point arithmetic with a decimal-safe library such as decimal.js, big.js, or java.math.BigDecimal. Store monetary values as integer cents or as DECIMAL(19,4) columns in the database, and perform all arithmetic in that representation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'pi1-acc-002',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Missing Decimal Precision Handling in Numeric Operations',
		description:
			'Identifies numeric operations that produce results without explicit precision control. When the output of a division or multiplication is assigned directly to a variable without rounding or truncation, downstream consumers may receive values with non-deterministic fractional digits, violating output accuracy requirements.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'=\\s*[a-zA-Z_$][\\w$]*\\s*\\/\\s*[a-zA-Z_$\\d][\\w$]*(?!\\s*[;,\\)]?\\s*\\.(?:toFixed|toPrecision|round|floor|ceil|trunc|quantize|setScale))',
			flags: 'g',
			explanation:
				'Matches division assignments where the result is not immediately passed through a precision-clamping method call.',
		},
		remediation:
			'Apply an explicit rounding or precision-fixing call immediately after division: e.g., `(a / b).toFixed(2)` in JavaScript/TypeScript, `round(a / b, 2)` in Python, or `BigDecimal.divide(divisor, scale, RoundingMode.HALF_UP)` in Java. Document the intended scale for each numeric field.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'pi1-acc-003',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'No Rounding Mode Specification in Financial Calculations',
		description:
			'Detects rounding calls that omit an explicit rounding mode. Default rounding behaviour differs across languages, runtimes, and library versions. Failing to specify a rounding mode (e.g., HALF_UP, HALF_EVEN) means that the same logical calculation may produce different results in different environments, undermining processing integrity.',
		severity: 'high',
		languages: ['java', 'python', 'csharp', 'typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:Math\\.round|BigDecimal\\.divide|setScale|Decimal\\.toFixed|round)\\s*\\([^,)]+\\)',
			flags: 'g',
			explanation:
				'Matches round/divide calls that provide only one argument, indicating no rounding mode is supplied.',
		},
		remediation:
			'Always supply a rounding mode: Java — `BigDecimal.divide(divisor, scale, RoundingMode.HALF_UP)`; Python — `decimal.ROUND_HALF_UP`; .NET — `Math.Round(value, digits, MidpointRounding.AwayFromZero)`. Document the chosen rounding strategy in a central constants file or configuration.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'pi1-acc-004',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Missing Currency Conversion Accuracy Controls',
		description:
			'Identifies currency conversion logic that lacks rate-source validation, timestamp binding, or scale specification. Currency conversions performed with stale or imprecise exchange rates introduce systematic errors into financial outputs. Processing integrity requires that conversion operations record the rate used, its timestamp, and that the result is rounded to the target currency scale.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:convert|exchange|fx|forex|rate)\\s*[\\(\\*]\\s*(?:amount|value|price|sum|total)',
			flags: 'gi',
			explanation:
				'Matches identifiers suggesting currency conversion applied to a monetary quantity, without evidence of rate validation.',
		},
		remediation:
			'Bind every conversion to a rate record that carries a source identifier, effective timestamp, and bid/ask spread. Round the converted amount to the canonical decimal places of the target currency (ISO 4217 exponent). Log the rate record ID alongside every converted value in your audit trail.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'pi1-acc-005',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'No Checksum Validation on Received Data',
		description:
			'Detects data-ingestion paths (file reads, API response parsing, message deserialization) that do not verify a checksum or CRC before processing the payload. Without checksum validation, corrupted or partially-transmitted data may be processed as if it were complete and accurate, violating processing-integrity accuracy guarantees.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'rust', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:checksum|crc32|crc16|adler|fletcher|luhn)',
			flags: 'i',
			explanation:
				'Flags files that perform data ingestion (readFile, fetch, parse) but contain no reference to checksum or CRC verification functions.',
		},
		remediation:
			'Compute or verify a CRC-32 or SHA-256 checksum on every inbound data payload before parsing. Reject and quarantine payloads whose computed checksum does not match the transmitted or stored checksum. Log the validation result in the processing audit trail.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'pi1-acc-006',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Missing Hash Verification Before Data Processing',
		description:
			'Identifies data-processing pipelines that load files or blobs without verifying a cryptographic hash of the input. An attacker or a storage fault can silently corrupt data; processing corrupted data without hash verification produces inaccurate outputs and violates the PI1.3 accuracy criterion.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'rust', 'csharp', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:sha256|sha-256|sha512|sha-512|md5|hmac|digest|hash(?:Sum|Value|Check))',
			flags: 'i',
			explanation:
				'Flags processing files that lack any reference to a hash/digest function, suggesting data integrity is not verified before use.',
		},
		remediation:
			'Compute a SHA-256 hash of each input artefact at ingestion time and compare it against an authoritative digest stored separately (e.g., a manifest file or database record). Abort processing and raise an alert if the digests do not match. Store the verified hash in the processing log.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'pi1-acc-007',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'No Data Completeness Checks After Transformation',
		description:
			'Detects transformation functions that produce an output collection without verifying that the output count matches the input count. Silent row drops during ETL or data-mapping operations yield incomplete datasets that appear complete, directly violating the completeness dimension of processing integrity.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:\\.map\\(|\\.filter\\(|transform|process)(?:[^{}]+)(?:return|=>)(?:[^;{}]+)(?!(?:[\\s\\S]{0,500})(?:length|count|size|total)\\s*(?:===|==|!==|!=|>=|<=|>|<))',
			flags: 'g',
			explanation:
				'Matches data-transformation calls whose enclosing function scope does not include a count or length comparison that would validate completeness of the output.',
		},
		remediation:
			'After every transformation, assert that `output.length === input.length` (or the equivalent for your language). For filtering operations, log the drop count and the filter predicate. Include input and output record counts in the processing audit log.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'pi1-acc-008',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Missing Output Validation Before Persistence or Transmission',
		description:
			'Identifies output-producing functions that write results to a database, file, or network endpoint without running a validation schema or sanity check on the output values. Unvalidated output may contain out-of-range values, unexpected nulls, or structurally malformed records, all of which compromise accuracy.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:save|insert|update|upsert|write|send|publish|emit|put|post)\\s*\\([^)]*\\)(?!\\s*\\.(?:catch|then|finally)(?:[\\s\\S]{0,200})(?:valid|schema|assert|verify|check))',
			flags: 'gi',
			explanation:
				'Matches persistence or transmission calls that are not preceded or followed (within a short window) by a validation call.',
		},
		remediation:
			'Apply a schema-validation step (e.g., Zod, Joi, JSON Schema, Bean Validation) to every output object immediately before writing or transmitting it. Reject and flag records that fail validation; do not silently coerce or truncate field values.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'pi1-acc-009',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'No Reconciliation Mechanism in Financial Processing Pipelines',
		description:
			'Detects financial or transactional processing modules that lack any reconciliation logic. Reconciliation — comparing independently derived totals against one another — is a core detective control for processing accuracy. Its absence means that discrepancies between input and output values may go undetected indefinitely.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:reconcil|recon|balanceCheck|crossCheck|cross.check|tally|settle)',
			flags: 'i',
			explanation:
				'Flags source files in a financial pipeline that contain no reference to reconciliation functions or variables.',
		},
		remediation:
			'Implement end-of-period and end-of-batch reconciliation: independently sum input amounts, output amounts, and fees; compare them against control totals from the upstream system and the general ledger. Log any variance above the materiality threshold and halt further processing until reconciled.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'pi1-acc-010',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Missing Audit Log Completeness — No Entry Count or Integrity Check',
		description:
			'Identifies audit-logging implementations that record events without verifying or asserting the completeness of the log itself. An audit log that can silently lose entries or be tampered with provides a false assurance of completeness. PI1.3 requires that audit records faithfully reflect all processing activity.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:audit|log|logger|event)\\s*\\.(?:log|write|record|append|info|warn|error)\\s*\\([^)]*\\)',
			flags: 'gi',
			explanation:
				'Matches audit/log write calls to flag files where log completeness controls (sequence numbers, HMAC chaining, count assertions) should also be present.',
		},
		remediation:
			'Add a monotonically increasing sequence number to each audit entry. Chain entries by including the hash of the previous entry in each new record (append-only hash chain). Periodically verify the chain and alert on any gap or hash mismatch. Use a write-once log store or WORM-compliant medium for regulated environments.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'pi1-acc-011',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'No Sequence Number Validation for Ordered Event Streams',
		description:
			'Detects event consumers or message-queue processors that do not validate the sequence number or offset of incoming messages. Out-of-order or duplicate processing of financial events causes incorrect running balances and aggregate calculations, directly violating the accuracy requirements of PI1.3.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:sequence|seqNum|seq_num|offset|messageId|msg_id|eventId|event_id)\\s*(?:===|==|!==|!=|>|<|>=|<=|\\+\\+|\\+=)',
			flags: 'i',
			explanation:
				'Flags event-processing files that contain no comparison or increment of a sequence number or offset variable, suggesting ordering is not validated.',
		},
		remediation:
			'Track the last-processed sequence number or offset in durable storage. Before processing each message, assert that its sequence number equals lastSequence + 1. Reject or re-queue out-of-order messages; deduplicate messages whose sequence number is less than or equal to the last processed value.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'pi1-acc-012',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Missing Batch Processing Control Totals',
		description:
			'Identifies batch-processing routines that iterate over collections and accumulate results without computing or verifying control totals (hash totals, record totals, amount totals). Control totals are a foundational completeness and accuracy control for batch operations and are required by PI1.3.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:for\\s*\\(|forEach|for\\s+\\w+\\s+in|while\\s*\\()(?:[\\s\\S]{1,800})(?:push|append|add|accumulate)(?!(?:[\\s\\S]{0,600})(?:controlTotal|control_total|hashTotal|hash_total|batchTotal|batch_total|recordCount|record_count))',
			flags: 'g',
			explanation:
				'Matches loops that accumulate results into a collection but where no control-total variable is evident in the surrounding scope.',
		},
		remediation:
			'Before starting a batch, obtain control totals from the upstream source (expected record count, sum of key amounts, hash total of IDs). After processing, compute the same totals from the output. Compare them and reject the batch if they do not match. Record both totals in the batch audit log.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'pi1-acc-013',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'No Record Count Verification After Database Operations',
		description:
			'Detects bulk database operations (INSERT, UPDATE, DELETE, bulk copy) that do not check the affected-row count against an expected value. A mismatch between the intended and actual count indicates silent data loss or duplication, violating processing accuracy.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:bulkInsert|insertMany|executeBatch|executeUpdate|batchUpdate|bulkWrite|copyFrom)\\s*\\([^)]*\\)(?![\\s\\S]{0,300}(?:rowCount|affectedRows|affected_rows|rowsAffected|rows_affected|count\\s*(?:===|==|!==|!=)))',
			flags: 'gi',
			explanation:
				'Matches bulk-write database calls that are not followed (within a reasonable scope) by a check of the returned affected-row count.',
		},
		remediation:
			'Capture the row count returned by every bulk DML operation and compare it against the expected count derived from the input dataset. Throw an error and roll back the transaction if the counts differ. Log both values in the audit trail.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'pi1-acc-014',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Missing Field Completeness Validation in Schema Definitions',
		description:
			'Identifies database schema or API schema definitions that do not mark required fields as NOT NULL or required. Optional fields without a default allow records to be persisted with incomplete information, silently degrading the accuracy of downstream reports and calculations.',
		severity: 'medium',
		languages: ['any'],
		targets: ['schema', 'migration'],
		pattern: {
			type: 'regex',
			value:
				'(?:CREATE\\s+TABLE|ALTER\\s+TABLE)(?:[\\s\\S]{1,2000})(?:DECIMAL|NUMERIC|FLOAT|DOUBLE|INT|BIGINT|VARCHAR|TEXT|DATE|TIMESTAMP)(?!(?:[\\s\\S]{0,60})NOT\\s+NULL)',
			flags: 'gi',
			explanation:
				'Matches column definitions in DDL statements whose type is not followed by a NOT NULL constraint, indicating potentially nullable fields that may require completeness guarantees.',
		},
		remediation:
			'For every field that must be present to produce accurate outputs, add a NOT NULL constraint (or `required: true` in a JSON/OpenAPI schema). For fields that are legitimately optional, add an explicit DEFAULT value and document why the field may be absent. Review nullable fields during schema review gates.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'pi1-acc-015',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'No Null Value Handling in Aggregation and Calculation Functions',
		description:
			'Detects aggregation or arithmetic expressions that do not guard against null/undefined inputs. In most languages, arithmetic involving null produces null or NaN, silently corrupting aggregated totals. PI1.3 accuracy requires that null propagation be explicitly handled before any calculation.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:reduce|aggregate|sum|average|mean|total|acc\\s*\\+|total\\s*\\+)(?:[^;{]{0,120})(?!(?:null|undefined|NaN|None|nil|0\\s*\\|\\||\\?\\?|isNull|isNaN|notNull|COALESCE|ISNULL|ifNull))',
			flags: 'gi',
			explanation:
				'Matches aggregation operations that do not include a null/NaN guard in their immediate context, suggesting null values could silently corrupt the result.',
		},
		remediation:
			'Before including a value in any sum, average, or accumulation, explicitly handle nulls: use the nullish coalescing operator (`?? 0`), COALESCE in SQL, `orElse(0)` in Java Optionals, or equivalent. Log occurrences of null values encountered in mandatory fields as data quality warnings.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'pi1-acc-016',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Missing Default Value Documentation for Configuration Parameters',
		description:
			'Identifies configuration files or environment-variable declarations that define a default value without an accompanying comment explaining the value, its unit, and its accuracy implications. Undocumented defaults are silently applied when the explicit value is absent, potentially causing incorrect calculations in production.',
		severity: 'low',
		languages: ['any'],
		targets: ['config'],
		pattern: {
			type: 'regex',
			value:
				'(?:default|DEFAULT|Default)\\s*[:=]\\s*[\\d\\.]+(?!(?:[\\s]*(?:\\/\\/|#|/\\*|<!--)[^\\n]{5,}))',
			flags: 'g',
			explanation:
				'Matches numeric default-value assignments that are not immediately followed by a comment, indicating the default is undocumented.',
		},
		remediation:
			'Add an inline comment to every numeric default value that explains: the unit (e.g., milliseconds, cents, basis points), the rationale for the chosen default, and the accuracy impact if the default is used in production. Validate configuration at startup and warn (or fail) if critical numeric parameters are at their default values in a production environment.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'pi1-acc-017',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'No Verification of Calculated or Derived Fields',
		description:
			'Detects getter methods or computed property accessors that derive a value from other fields without validating the result against known constraints (e.g., non-negative amounts, range checks). Derived fields can silently return incorrect values when their input fields are corrupt or out-of-range.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'ast',
			value:
				'MethodDefinition[kind="get"] > FunctionExpression > BlockStatement:not(:has(IfStatement, ThrowStatement, AssertStatement))',
			explanation:
				'Targets getter methods whose bodies contain no conditional guard or throw statement, meaning the calculated value is returned without any range or sanity validation.',
		},
		remediation:
			'Add a post-calculation assertion in every getter or computed-field method: verify the result is within the expected range, is not NaN/Infinity, and has the correct sign. Throw a descriptive error if the assertion fails so that invalid derived values are surfaced immediately rather than propagated silently.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'pi1-acc-018',
		criteria: 'PI1.3',
		category: 'integrity',
		title: 'Missing Report Accuracy Validation — No Totals Cross-Check in Report Generation',
		description:
			'Identifies report-generation code that formats and emits data without performing a cross-check that verifies the sum of line items equals the declared total, or that summarised figures match the detail records. Reports that present internally inconsistent numbers violate the accuracy and completeness requirements of PI1.3.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: [
				'rules:',
				'  - id: pi1-acc-018-report-accuracy',
				'    patterns:',
				'      - pattern: |',
				'          function $REPORT(...) {',
				'            ...',
				'            return $OUTPUT;',
				'          }',
				'      - pattern-not: |',
				'          function $REPORT(...) {',
				'            ...',
				'            if ($TOTAL !== $SUM) { ... }',
				'            ...',
				'            return $OUTPUT;',
				'          }',
				'    message: Report function returns output without cross-checking line-item totals against declared totals.',
				'    languages: [javascript, typescript, python, java, go]',
				'    severity: ERROR',
			].join('\n'),
			explanation:
				'Semgrep rule that matches report-returning functions that lack an equality check between a total variable and a computed sum, indicating no cross-check of aggregate accuracy before the report is emitted.',
		},
		remediation:
			'Before emitting any report, recompute the summary totals from the underlying line-item data and assert they equal the values declared in the report header or footer. Log any discrepancy as a critical data-quality event and withhold the report from distribution until the variance is explained and resolved.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
];
