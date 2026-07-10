/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const pi1InputRules: ISoc2Rule[] = [

	// ─── PI1.1 Input Integrity (rules 001–018) ────────────────────────────────

	{
		id: 'pi1-inp-001',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'Missing input schema validation',
		description:
			'Request handler processes user-supplied input without validating it against a defined schema. Unvalidated inputs can carry malformed, unexpected, or malicious data that corrupts processing pipelines and undermines data integrity.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:validate|schema\\.parse|ajv|joi\\.object|zod\\.object|class-validator|jsonschema|cerberus|marshmallow|validator\\.validate|binding\\.result|BindingResult)',
			flags: 'i',
			explanation:
				'Flags route or handler functions that read from req.body, request.json(), or @RequestBody without any adjacent schema-validation call, indicating raw unvalidated input flows into business logic.',
		},
		remediation:
			'Validate all inbound payloads against a strict schema before processing. Use a library such as Zod or Joi (TypeScript/JavaScript), Pydantic or Marshmallow (Python), Jakarta Bean Validation (Java), or go-playground/validator (Go). Reject requests that fail validation with HTTP 422.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-002',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'No JSON schema validation on incoming payload',
		description:
			'The application parses JSON from an incoming request but does not validate the parsed object against a JSON Schema definition, allowing structurally invalid or unexpectedly typed payloads to propagate through the system.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:JSON\\.parse|json\\.loads|objectMapper\\.readValue|json\\.Unmarshal)\\s*\\([^)]*\\)(?![\\s\\S]{0,400}(?:validate|schema|ajv|jsonschema|ObjectMapper.*schema|json\\.Valid))',
			flags: 'i',
			explanation:
				'Detects JSON deserialization calls that are not followed within 400 characters by a schema-validation step, indicating the parsed object is used without structural verification.',
		},
		remediation:
			'After deserialising JSON input, validate the resulting object against a JSON Schema (draft-07 or later) using Ajv (Node.js), jsonschema (Python), or an equivalent library. Reject documents that do not conform to the schema.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-inp-003',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'Missing required field validation',
		description:
			'Handler code accesses request body properties directly without first asserting that mandatory fields are present and non-null. Absent required fields can cause null-reference errors, silent data truncation, or downstream processing failures.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'req\\.body\\.(?:[a-zA-Z_][a-zA-Z0-9_]*)(?![\\s\\S]{0,300}(?:required|NotNull|NotEmpty|isRequired|\\!\\s*req\\.body\\.|typeof.*undefined))',
			flags: 'i',
			explanation:
				'Matches direct accesses to request body fields that are not guarded by a required-field check, indicating missing presence validation.',
		},
		remediation:
			'Define a schema with all mandatory fields marked as required and validate the full payload before accessing individual properties. Return HTTP 400 with a field-level error message when required fields are absent.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-004',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'No data type enforcement on input fields',
		description:
			'Input fields are used in computations or database queries without verifying that they match the expected data type. Type coercion by the runtime can silently convert values in unexpected ways, leading to logic errors or injection vulnerabilities.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'parseInt\\s*\\(\\s*req\\.(?:body|params|query)\\.|parseFloat\\s*\\(\\s*req\\.(?:body|params|query)\\.|Number\\s*\\(\\s*req\\.(?:body|params|query)\\.',
			flags: 'i',
			explanation:
				'Detects type-coercion calls (parseInt, parseFloat, Number) applied directly to request data, which masks the absence of explicit type validation and can silently mishandle non-numeric inputs.',
		},
		remediation:
			'Enforce types at the schema level using strict type constraints (e.g., z.number() in Zod, "type": "integer" in JSON Schema). Reject inputs that do not match the expected type rather than coercing them silently.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-005',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'Missing string length limits on input fields',
		description:
			'String input fields are accepted and stored without enforcing a maximum length constraint. Oversized strings can exhaust memory, cause buffer-adjacent issues, trigger database truncation errors, or be exploited for denial-of-service.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:maxLength|max_length|MaxLength|max\\s*:\\s*\\d+|minlength|maxlength|length\\s*<=|len\\s*<=|varchar\\(|character varying\\()',
			flags: 'i',
			explanation:
				'Flags string input fields in schema definitions or validation code that lack any maximum-length constraint, indicating unbounded string acceptance.',
		},
		remediation:
			'Apply maximum length constraints to every string field in both the validation schema and the database column definition. Use z.string().max(N), @MaxLength(N), or "maxLength": N in JSON Schema. Align the validator limit with the database column size.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'pi1-inp-006',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'No numeric range validation on input fields',
		description:
			'Numeric input fields such as quantities, amounts, ages, or scores are accepted without validating minimum and maximum bounds. Out-of-range values can cause arithmetic overflow, negative inventory, or incorrect business-rule application.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:min\\s*:\\s*\\d|max\\s*:\\s*\\d|minimum\\s*:\\s*\\d|maximum\\s*:\\s*\\d|Min\\s*\\(|Max\\s*\\(|Range\\s*\\(|z\\.number\\(\\)\\.min|z\\.number\\(\\)\\.max|clamp)',
			flags: 'i',
			explanation:
				'Flags numeric fields in validation schemas or handler code that have no minimum or maximum boundary defined, indicating unconstrained numeric input.',
		},
		remediation:
			'Define explicit minimum and maximum values for all numeric inputs in the validation schema. Use z.number().min(0).max(10000) in Zod, @Min/@Max annotations in Java, or "minimum"/"maximum" in JSON Schema. Reject out-of-range values with a descriptive error.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-007',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'Missing regex pattern validation for structured input fields',
		description:
			'Structured input fields such as usernames, postal codes, or identifiers are accepted without validating them against a regular-expression pattern, allowing structurally invalid values to be stored or processed.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:pattern\\s*:|regex\\s*:|match\\s*\\(|test\\s*\\(|Pattern\\s*\\(|@Pattern|z\\.string\\(\\)\\.regex|re\\.match|regexp\\.MatchString)',
			flags: 'i',
			explanation:
				'Flags input fields for structured values (usernames, codes, identifiers) that have no regular-expression pattern constraint applied during validation.',
		},
		remediation:
			'Apply a strict regex pattern to all structured string fields. Use z.string().regex(/^[a-z0-9_-]{3,30}$/) in Zod, @Pattern(regexp = "...") in Java Bean Validation, or "pattern": "..." in JSON Schema. Document the pattern rationale alongside the constraint.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-008',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'No email format validation on email input fields',
		description:
			'Email address fields are stored and used (e.g., for sending notifications or as account identifiers) without validating RFC 5322 format. Invalid email addresses cause delivery failures, account lockout, and data integrity issues.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:req\\.body\\.email|request\\.form\\.get\\s*\\(["\']email["\']\\)|params\\.get\\s*\\(["\']email["\']\\))(?![\\s\\S]{0,300}(?:isEmail|EmailAddress|@Email|z\\.string\\(\\)\\.email|email_validator|valid_email|validateEmail))',
			flags: 'i',
			explanation:
				'Matches code that reads an email field from the request but lacks a nearby email-format validation call, indicating the email value is used without format verification.',
		},
		remediation:
			'Validate email fields with a proven library: z.string().email() in Zod, @Email in Jakarta Bean Validation, email-validator in Python, or net/mail.ParseAddress in Go. Do not rely on a hand-rolled regex for email validation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-inp-009',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'Missing phone number format validation',
		description:
			'Phone number input fields are stored or used for communication purposes without validating E.164 or locale-specific format. Malformed phone numbers cause delivery failures, silent data corruption, and potential abuse of telephony APIs.',
		severity: 'low',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:req\\.body\\.phone|request\\.form\\.get\\s*\\(["\']phone["\']\\)|body\\.phoneNumber|body\\.phone_number)(?![\\s\\S]{0,300}(?:libphonenumber|PhoneNumber|phone_validator|isMobilePhone|isPhoneNumber|\\+?[0-9]{7,15}|E\\.164))',
			flags: 'i',
			explanation:
				'Detects code that reads a phone or phoneNumber field from the request body without a nearby phone-number format validation, indicating the value is trusted without structural verification.',
		},
		remediation:
			'Validate phone numbers using libphonenumber-js (JavaScript), phonenumbers (Python), or Google libphonenumber (Java/Go). Accept only E.164-formatted values (+CountryCodeNumber) and reject all other formats.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-010',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'No URL format validation on URL input fields',
		description:
			'URL fields accepted from user input are used directly in HTTP requests, redirects, or stored as references without validating their format and scheme. Invalid or attacker-controlled URLs enable SSRF, open redirect, and data-integrity issues.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:req\\.body\\.url|body\\.callbackUrl|body\\.redirectUrl|body\\.webhook|body\\.endpoint)(?![\\s\\S]{0,400}(?:isURL|z\\.string\\(\\)\\.url|URL\\s*\\(|urllib\\.parse|url\\.ParseRequestURI|validateUrl|allowedHosts|urlAllowlist))',
			flags: 'i',
			explanation:
				'Matches code that reads a URL-type field from the request body without a subsequent URL-format validation or host-allowlist check.',
		},
		remediation:
			'Parse and validate URL inputs using the platform URL constructor (new URL(value)), z.string().url() in Zod, or urllib.parse in Python. After format validation, also verify the host against an explicit allowlist to prevent SSRF.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-inp-011',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'Missing date format validation on date input fields',
		description:
			'Date and datetime input fields are parsed or stored without validating their format or range. Invalid date strings can cause runtime exceptions, incorrect sorting, or silent storage of sentinel values like epoch-zero.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:new Date\\s*\\(\\s*req\\.body\\.|datetime\\.strptime\\s*\\(\\s*request\\.|LocalDate\\.parse\\s*\\(\\s*(?:request|param)|time\\.Parse\\s*\\([^,]*,\\s*(?:r\\.FormValue|c\\.Query))(?![\\s\\S]{0,300}(?:isNaN|isValid|Invalid Date|z\\.date|DateTimeFormat|ValueError|ParseException))',
			flags: 'i',
			explanation:
				'Detects date-parsing calls that receive user-controlled strings but lack an adjacennt isValid or format-error check, meaning invalid dates propagate silently.',
		},
		remediation:
			'Validate date inputs against an ISO 8601 format using z.string().datetime() in Zod, @DateTimeFormat in Spring, or datetime.strptime with explicit format string and error handling in Python. Enforce sensible range constraints (e.g., no dates before 1900 or more than 10 years in the future).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-012',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'No enum value validation on categorical input fields',
		description:
			'Input fields that accept a fixed set of values (e.g., status, role, category, currency) do not validate the submitted value against the permitted set. Out-of-enum values can bypass business rules, corrupt state machines, or trigger unexpected code paths.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'req\\.body\\.(?:status|role|type|category|action|currency|priority|state)(?![\\s\\S]{0,300}(?:enum|z\\.enum|oneOf|includes\\s*\\(|in\\s*\\[|\\bENUM\\b|@Enumerated|isIn|allowedValues|validValues))',
			flags: 'i',
			explanation:
				'Matches code that reads a categorical field (status, role, type, etc.) from the request without a nearby enum/allowlist check, indicating the value is accepted without constraint.',
		},
		remediation:
			'Use z.enum([\'value1\', \'value2\']) in Zod, "enum": [...] in JSON Schema, or @Enumerated with a defined Java enum. Reject any value not in the permitted set with HTTP 422 and a descriptive error identifying the allowed values.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-013',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'Missing array size limits on array input fields',
		description:
			'Array or list input fields are processed without enforcing a maximum item count. Unbounded arrays can exhaust server memory during iteration, cause O(n²) processing degradation, or be used for denial-of-service attacks.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:req\\.body\\.(?:[a-zA-Z_][a-zA-Z0-9_]*)\\s*\\.forEach|for\\s*\\(.*of\\s+req\\.body\\.|request\\.json\\(\\)\\[)(?![\\s\\S]{0,400}(?:maxItems|max_items|MaxSize|length\\s*<=|len\\s*<=|z\\.array\\(.*\\.max|slice\\s*\\(\\s*0\\s*,))',
			flags: 'i',
			explanation:
				'Detects array iteration over request-body arrays without a preceding or nearby maximum-size guard, indicating unbounded iteration on user-controlled data.',
		},
		remediation:
			'Enforce a maximum item count on all array input fields using z.array(...).max(N) in Zod, "maxItems": N in JSON Schema, or @Size(max = N) in Jakarta Bean Validation. Choose limits appropriate to your use-case and document the rationale.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'pi1-inp-014',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'No nested object depth limits on input payloads',
		description:
			'JSON or object payloads are processed without restricting recursion depth. Deeply nested structures exploit recursive parsers and validators causing stack overflows, excessive CPU usage, or prototype-pollution gadget chains.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:maxDepth|max_depth|MAX_DEPTH|nestingLimit|recursion_limit|depth\\s*<=\\s*\\d|flatDepth|JSON\\.parse.*reviver)',
			flags: 'i',
			explanation:
				'Flags JSON parsing or recursive-traversal code that contains no reference to a depth limit, leaving the application open to stack-overflow attacks via deeply nested payloads.',
		},
		remediation:
			'Limit JSON nesting depth before passing input to business logic. In Node.js use a custom JSON.parse reviver that tracks depth. In Python set a recursion limit for custom parsers. Reject payloads exceeding depth 20. Use flat data representations where possible.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-015',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'Missing file upload validation',
		description:
			'File upload handlers accept files without validating the file name, size, MIME type, or content signature. Malicious uploads can overwrite server files, introduce malware, or trigger server-side processing vulnerabilities.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:req\\.file|req\\.files|request\\.files|multipart\\.File|formFile\\s*\\()(?![\\s\\S]{0,500}(?:mimetype|mime_type|content_type|originalname|filename|filesize|maxSize|maxFileSize|allowedTypes|magic\\.detect|filetype))',
			flags: 'i',
			explanation:
				'Detects file-upload access (req.file, request.files, multipart.File) without a nearby MIME-type, size, or file-type validation check.',
		},
		remediation:
			'Validate uploaded files on all dimensions: (1) maximum size, (2) allowed MIME types via content-type header, (3) actual file signature (magic bytes) using a library such as file-type (Node.js) or python-magic (Python), and (4) safe filename. Store uploads outside the web root and never execute them.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'pi1-inp-016',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'No content type validation on incoming requests',
		description:
			'API endpoints process request bodies without checking the Content-Type header. Accepting unexpected content types can cause parsers to misinterpret payloads, bypass input-validation layers, or trigger content-sniffing attacks.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:content-type|contentType|Content-Type|req\\.is\\s*\\(|request\\.content_type|r\\.Header\\.Get\\s*\\(["\']Content-Type)',
			flags: 'i',
			explanation:
				'Flags request handler code that parses a body (JSON, multipart, form-data) without checking or enforcing the Content-Type header, indicating content-type agnostic parsing.',
		},
		remediation:
			'Reject requests whose Content-Type does not match the expected media type for the endpoint (e.g., application/json, multipart/form-data). Return HTTP 415 Unsupported Media Type when the Content-Type is absent or incorrect.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'pi1-inp-017',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'Missing encoding validation on text input fields',
		description:
			'Text input fields are processed without verifying that the content is valid UTF-8 or the declared encoding. Invalid encoding sequences can bypass downstream security controls, corrupt database records, or cause parser crashes in encoding-sensitive components.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:Buffer\\.isEncoding|TextDecoder|chardet|charsetdetect|charset\\.detect|iconv|codecs\\.decode|StandardCharsets\\.UTF_8|unicode\\.Is|utf8\\.Valid|isValidUTF8)',
			flags: 'i',
			explanation:
				'Flags request-processing code that reads text from the body or query parameters without performing any character-encoding validation, indicating reliance on implicit encoding assumptions.',
		},
		remediation:
			'Validate that all incoming text data is well-formed UTF-8 before processing. In Node.js use Buffer.isEncoding or the TextDecoder API with error-mode "fatal". In Python decode bytes with errors="strict". In Go use utf8.Valid(). Reject requests containing invalid byte sequences with HTTP 400.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'pi1-inp-018',
		criteria: 'PI1.1',
		category: 'integrity',
		title: 'No character whitelist enforcement on free-text input fields',
		description:
			'Free-text input fields such as names, descriptions, and comments accept any Unicode character without restricting to a permitted character set. Unrestricted character input enables injection attacks, homograph attacks, and data that breaks downstream systems expecting ASCII or a limited character set.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:whitelist|allowedChars|allowedCharacters|characterWhitelist|sanitize|dompurify|bleach\\.clean|escapeHtml|xss|stripTags|\\\\p\\{L\\}|[\\^a-zA-Z0-9\\s])',
			flags: 'i',
			explanation:
				'Flags free-text input fields in form-processing or API handler code that contain no reference to a character whitelist, sanitisation function, or character-class restriction, indicating all Unicode code points are accepted without filtering.',
		},
		remediation:
			'Define an explicit character allowlist for every free-text field based on business requirements (e.g., letters, digits, common punctuation). Use a regex pattern constraint in the validation schema. For fields that accept rich content, apply a context-aware HTML sanitiser such as DOMPurify (JavaScript) or bleach (Python) rather than a blanket strip.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},
];
