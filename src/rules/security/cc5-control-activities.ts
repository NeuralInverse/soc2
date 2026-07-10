/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc5Rules: ISoc2Rule[] = [
	// ── CC5.1 – Policies and Procedures ──────────────────────────────────────────

	{
		id: 'cc5-001',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Missing Content-Security-Policy Header',
		description:
			'HTTP responses do not set a Content-Security-Policy (CSP) header. Without CSP, browsers cannot enforce restrictions on which resources may be loaded, leaving the application vulnerable to cross-site scripting (XSS) and data-injection attacks. CC5.1 requires control activities that include policies enforced at the application layer.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: 'content.?security.?policy|helmet\\(|csp\\(',
			flags: 'i',
			explanation:
				'Checks that server-side middleware setup contains a reference to content-security-policy, helmet, or a CSP helper. Absence indicates the header is likely not set.',
		},
		remediation:
			'Add a Content-Security-Policy header to all HTTP responses. Use a middleware library such as Helmet (Node.js) or equivalent. Define a strict policy with explicit allowlists for scripts, styles, and other resource types. Test the policy in report-only mode before enforcing it.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-secure-headers/',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
		],
	},

	{
		id: 'cc5-002',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Missing HTTP Strict-Transport-Security Header',
		description:
			'The application does not configure an HTTP Strict-Transport-Security (HSTS) header. Without HSTS, browsers may connect over plain HTTP, exposing traffic to man-in-the-middle attacks. SOC 2 CC5.1 mandates control activities that protect data in transit.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: 'strict.transport.security|hsts|includeSubDomains',
			flags: 'i',
			explanation:
				'Checks for the absence of any HSTS header configuration. If no reference to strict-transport-security or an HSTS helper is found, the header is not being set.',
		},
		remediation:
			'Configure the Strict-Transport-Security header with a max-age of at least 31536000 (one year) and include the includeSubDomains directive. Add the preload directive once confirmed stable. Ensure all HTTP traffic is redirected to HTTPS before enabling HSTS.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-secure-headers/',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
		],
	},

	{
		id: 'cc5-003',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Missing X-Frame-Options Header',
		description:
			'HTTP responses do not include the X-Frame-Options header, leaving the application vulnerable to clickjacking attacks where malicious pages embed the app in an iframe. CC5.1 requires application-layer control activities to prevent unauthorized actions.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: 'x.frame.options|frameguard|DENY|SAMEORIGIN',
			flags: 'i',
			explanation:
				'Detects the absence of X-Frame-Options header configuration. If no reference to x-frame-options, frameguard, DENY, or SAMEORIGIN is found in middleware setup, clickjacking protection is missing.',
		},
		remediation:
			'Add the X-Frame-Options header set to DENY or SAMEORIGIN on all HTTP responses. Additionally consider using the Content-Security-Policy frame-ancestors directive as a more flexible modern alternative.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/Clickjacking',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
		],
	},

	{
		id: 'cc5-004',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Missing X-Content-Type-Options Header',
		description:
			'HTTP responses do not include the X-Content-Type-Options: nosniff header. Without this header, browsers may attempt to infer the content type, which can lead to MIME-sniffing attacks where malicious content is executed as a different type.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: 'x.content.type.options|nosniff',
			flags: 'i',
			explanation:
				'Detects the absence of X-Content-Type-Options header configuration. If no reference to x-content-type-options or nosniff is found, browsers may perform MIME sniffing.',
		},
		remediation:
			'Add X-Content-Type-Options: nosniff to all HTTP responses. This prevents browsers from MIME-sniffing responses. Use a security middleware library to set all security headers consistently.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-secure-headers/',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
		],
	},

	{
		id: 'cc5-005',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Overly Permissive CORS Configuration',
		description:
			'The application configures CORS with a wildcard origin (`Access-Control-Allow-Origin: *`). This allows any origin to make cross-origin requests, bypassing the same-origin policy and exposing authenticated endpoints to malicious third-party sites.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'cors\\(\\{[^}]*origin\\s*:\\s*["\']?\\*["\']?|Access-Control-Allow-Origin["\']?\\s*[,:]\\s*["\']?\\*',
			flags: 'i',
			explanation:
				'Matches wildcard CORS origin configurations in CORS middleware options or response headers. Flags patterns like cors({ origin: "*" }) and Access-Control-Allow-Origin: *.',
		},
		remediation:
			'Replace wildcard CORS origins with an explicit allowlist of trusted domains. For authenticated endpoints never use `*`; validate the request Origin header against the allowlist and only reflect it in the response if it matches. Use environment-specific allowlists for development and production.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
		],
	},

	{
		id: 'cc5-006',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Missing API Rate Limiting',
		description:
			'API routes or server entry points do not configure a rate-limiting middleware. Without rate limiting, attackers can abuse endpoints with brute-force attacks, denial-of-service attempts, or credential stuffing. CC5.1 requires control activities that limit exposure.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: 'rate.?limit|ratelimit|throttle|express-rate-limit|slowDown|limiter',
			flags: 'i',
			explanation:
				'Detects the absence of any rate-limiting middleware configuration. If no rate-limit, throttle, or limiter reference is found, API endpoints are unprotected from abuse.',
		},
		remediation:
			'Implement rate limiting on all public API endpoints. Use a library such as express-rate-limit, ratelimiter, or equivalent. Apply stricter limits on sensitive endpoints (login, password reset, registration). Consider IP-based, user-based, and API-key-based limits. Log and alert on limit breaches.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc5-007',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Missing Request Body Size Limit',
		description:
			'The web server or API framework does not configure an explicit maximum request body size. Without this control, attackers can send extremely large payloads to exhaust server memory or disk resources, causing denial-of-service conditions.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: 'limit\\s*:\\s*[\'"][0-9]+[kKmMgG]?b?[\'"]|bodyParser.*limit|max.?body.?size|client_max_body_size|maxBodySize',
			flags: 'i',
			explanation:
				'Detects the absence of a body-size limit in request parsing middleware configuration. If no explicit size limit is found for body parsers, the server accepts arbitrarily large payloads.',
		},
		remediation:
			'Set an explicit maximum body size appropriate for your application (typically 1MB–10MB). In Express use bodyParser options like `{ limit: "1mb" }`. In nginx set `client_max_body_size`. Implement separate, stricter limits for file upload endpoints with additional file type and antivirus scanning.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/Buffer_overflow_attack',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc5-008',
		criteria: 'CC5.1',
		category: 'security',
		title: 'SQL Injection via String Concatenation',
		description:
			'Database queries are constructed by concatenating user-controlled input directly into SQL strings. This is a classic SQL injection vulnerability that can allow attackers to read, modify, or delete arbitrary database records, bypass authentication, and in some configurations execute system commands.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)\\s+[^;\'"`]*[\'"`]\\s*\\+\\s*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user|data)',
			flags: 'i',
			explanation:
				'Matches SQL keyword sequences followed by string concatenation of request-derived variables. Detects patterns like `"SELECT * FROM users WHERE id = " + req.params.id`.',
		},
		remediation:
			'Replace all dynamic SQL string concatenation with parameterized queries or prepared statements. Use an ORM that escapes inputs by default. Never concatenate user input into SQL strings. Apply input validation as a defense-in-depth measure, but always rely on parameterization as the primary control.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/SQL_Injection',
			'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-009',
		criteria: 'CC5.1',
		category: 'security',
		title: 'OS Command Injection via User Input',
		description:
			'Application code passes user-controlled data to shell execution functions (exec, spawn, system, popen) without sanitization. This enables command injection attacks where attackers can execute arbitrary operating-system commands with the privileges of the application process.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:exec|execSync|spawn|spawnSync|system|popen|shell_exec|passthru|proc_open)\\s*\\([^)]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user|data)',
			flags: 'i',
			explanation:
				'Matches shell execution function calls that include request-derived variables in their arguments. Detects patterns like `exec("ls " + req.query.path)` or `system(userInput)`.',
		},
		remediation:
			'Never pass user input to shell execution functions. Use language-native libraries for file system operations, process management, and other OS-level tasks. If shell execution is absolutely required, use an allowlist of permitted commands and arguments, and pass arguments as separate array elements to prevent shell interpretation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/Command_Injection',
			'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-010',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Path Traversal via User-Controlled File Path',
		description:
			'User-supplied input is used to construct file paths without normalization or containment checks. An attacker can supply sequences like `../../../etc/passwd` to read or write files outside the intended directory, potentially exposing sensitive configuration files, credentials, or system files.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:readFile|writeFile|createReadStream|open|fopen|file_get_contents|readFileSync)\\s*\\([^)]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Matches file read/write functions whose path argument includes request-derived variables. Detects patterns like `fs.readFile(req.query.filename)` where the path is not sanitized.',
		},
		remediation:
			'Resolve and validate all user-supplied file paths against an allowlist of permitted directories using `path.resolve()` followed by a check that the resolved path starts with the expected base directory. Reject any path containing `..` segments before resolution. Use random identifiers as file references instead of exposing actual file paths.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/Path_Traversal',
			'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-011',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Missing CSRF Protection on State-Changing Endpoints',
		description:
			'Web application does not implement CSRF token validation on state-changing HTTP methods (POST, PUT, PATCH, DELETE). Without CSRF protection, an attacker can trick authenticated users into submitting malicious requests from a third-party site.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: 'csrf|csurf|_csrf|csrfToken|X-CSRF-Token|SameSite=Strict|SameSite=Lax',
			flags: 'i',
			explanation:
				'Detects the absence of any CSRF protection mechanism. If no reference to CSRF tokens, the csurf middleware, or SameSite cookie attributes is found, state-changing endpoints may be unprotected.',
		},
		remediation:
			'Implement CSRF protection using the Synchronizer Token Pattern or Double Submit Cookie pattern. Use the csurf middleware in Express or an equivalent for your framework. Additionally set SameSite=Strict or SameSite=Lax on session cookies as a defense-in-depth measure. Validate the CSRF token on every state-changing request.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/csrf',
			'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-012',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Open Redirect Vulnerability',
		description:
			'The application redirects users to a URL constructed from user-supplied input without validating that the target URL is within the application domain. Attackers can craft links that redirect users to phishing or malware sites while appearing to originate from the legitimate application.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:res\\.redirect|redirect\\(|response\\.sendRedirect|http\\.Redirect|redirect_to)\\s*\\([^)]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Matches redirect calls whose URL argument includes request-derived variables. Detects patterns like `res.redirect(req.query.returnUrl)` where the destination is not validated.',
		},
		remediation:
			'Validate redirect targets against an allowlist of permitted URLs or domains. Use a mapping of safe redirect keys rather than accepting arbitrary URLs. If dynamic redirects are needed, parse the URL, validate the host against an allowlist, and reject any absolute URLs pointing to external domains.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc5-013',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Unvalidated File Upload Without Type Check',
		description:
			'File upload handlers accept uploaded files without validating their MIME type or file extension against an allowlist. Attackers can upload malicious files (web shells, scripts, executables) that may be executed by the server or delivered to users.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:multer|formidable|busboy|FileInterceptor|upload\\.single|upload\\.fields|request\\.files)(?![\\s\\S]{0,200}(?:mimetype|fileFilter|allowedTypes|whitelist|extension))',
			flags: 'i',
			explanation:
				'Matches file-upload middleware initialization patterns that are not followed within 200 characters by a MIME type filter or file extension allowlist. Indicates uploads are accepted without type validation.',
		},
		remediation:
			'Implement file type validation using both MIME type checking and file extension allowlisting. Use a magic byte check (e.g., file-type library) rather than relying solely on the Content-Type header. Store uploaded files outside the web root, rename them with random identifiers, and scan with antivirus before serving. Never execute uploaded files.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
			'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-014',
		criteria: 'CC5.1',
		category: 'security',
		title: 'XML External Entity (XXE) Injection',
		description:
			'XML parsing is performed without disabling external entity resolution. XXE vulnerabilities allow attackers to read local files, perform SSRF, or cause denial of service by including malicious external entity references in XML input.',
		severity: 'critical',
		languages: ['java', 'python', 'php', 'csharp', 'typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:XMLReader|DocumentBuilderFactory|SAXParserFactory|etree\\.parse|lxml|DOMParser|xml2js)(?![\\s\\S]{0,300}(?:FEATURE_EXTERNAL_GENERAL_ENTITIES|resolve_entities.*False|noent.*false))',
			flags: 'i',
			explanation:
				'Matches XML parser initialization that is not followed by explicit external-entity disabling options. Indicates the parser may process external entities by default.',
		},
		remediation:
			'Disable external entity resolution in all XML parsers. In Java, call `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)`. In Python lxml, use `resolve_entities=False`. In .NET, set `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`. Prefer JSON over XML for untrusted input.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
			'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-015',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Server-Side Template Injection',
		description:
			'User-controlled input is passed directly into a template engine render call without sanitization. Template injection can lead to arbitrary code execution when the template engine evaluates attacker-supplied expressions or directives.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'ruby', 'php', 'java'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:nunjucks\\.renderString|ejs\\.render|Handlebars\\.compile|pug\\.render|jinja2\\.Template|mustache\\.render)\\s*\\([^)]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Matches template engine render calls where the template string or data argument includes request-derived variables, indicating potential server-side template injection.',
		},
		remediation:
			'Never pass user input directly as a template string. Use template engines in their data-rendering mode where the template is a fixed string and user data is passed as context variables. Enable auto-escaping for HTML contexts. Use strict sandbox modes if dynamic templates are unavoidable.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection',
			'https://portswigger.net/research/server-side-template-injection',
		],
	},

	{
		id: 'cc5-016',
		criteria: 'CC5.1',
		category: 'security',
		title: 'LDAP Injection via Unsanitized Input',
		description:
			'LDAP queries are constructed using user-supplied input without escaping special LDAP characters. An attacker can inject LDAP metacharacters (e.g., `*`, `(`, `)`, `\\`) to manipulate query logic, bypass authentication, or extract directory information.',
		severity: 'critical',
		languages: ['java', 'python', 'csharp', 'typescript', 'javascript', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:ldap|LDAP|DirectorySearcher|LdapConnection)(?:[^;]{0,200})(?:Filter|search|query)\\s*[+=]+\\s*[^;]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Matches LDAP query construction patterns where filter strings are concatenated with user input. Detects patterns like `filter = "(&(uid=" + username + "))"` without escaping.',
		},
		remediation:
			'Escape all user input before including it in LDAP filters using the appropriate escaping functions for your LDAP library. In Java use `LdapEncoder.filterEncode()`. Use parameterized LDAP queries where supported. Validate and allowlist input format before using in queries.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/LDAP_Injection',
			'https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-017',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Missing Input Sanitization Before HTML Rendering',
		description:
			'User-supplied input is rendered directly into HTML without sanitization, creating XSS vulnerabilities. Attackers can inject malicious scripts that execute in the victim\'s browser, stealing session tokens, redirecting users, or performing actions on their behalf.',
		severity: 'critical',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:innerHTML|outerHTML|document\\.write|insertAdjacentHTML)\\s*[=+]\\s*[^;]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user|data)',
			flags: 'i',
			explanation:
				'Matches direct DOM manipulation using innerHTML or similar properties where request-derived variables are assigned. These patterns create XSS vulnerabilities when user data is injected into HTML.',
		},
		remediation:
			'Never use innerHTML or document.write with user-supplied content. Use `textContent` for plain text or a DOM-based sanitization library (e.g., DOMPurify) before using innerHTML. In server-rendered templates, ensure auto-escaping is enabled. Apply a Content Security Policy to reduce the impact of any XSS that occurs.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/xss/',
			'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-018',
		criteria: 'CC5.1',
		category: 'security',
		title: 'Missing Authorization Check on Route Handler',
		description:
			'Route handlers perform operations on resources without verifying that the authenticated user is authorized to access or modify that specific resource. This creates broken object-level authorization (BOLA/IDOR) vulnerabilities where users can access other users\' data by manipulating IDs.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:findById|findOne|getById|fetchById|findByPk)\\s*\\([^)]*(?:req\\.params|req\\.query|req\\.body)(?![\\s\\S]{0,200}(?:userId|ownerId|authorize|checkPermission|isOwner))',
			flags: 'i',
			explanation:
				'Matches database lookup calls using request-provided IDs that are not followed within 200 characters by an ownership or authorization check. Indicates potential IDOR vulnerability.',
		},
		remediation:
			'Always verify that the authenticated user is authorized to access the requested resource. Scope database queries to the authenticated user\'s ID rather than using user-supplied IDs directly. Implement object-level authorization checks before returning or modifying any resource. Use policy objects or authorization middleware to centralize access control logic.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-api-security/',
			'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
		],
	},

	// ── CC5.2 – Technology Controls ──────────────────────────────────────────────

	{
		id: 'cc5-019',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Hardcoded Secret or Password in Source Code',
		description:
			'Credentials, API keys, passwords, or cryptographic secrets are hardcoded directly in source code. These secrets are exposed to anyone with repository access and are difficult to rotate, violating the principle that secrets must be managed separately from code.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: '(?:password|passwd|secret|api_?key|apikey|access_?token|auth_?token|private_?key|client_?secret)\\s*[=:]+\\s*["\'][^"\'\\s]{8,}["\']',
			flags: 'i',
			explanation:
				'Matches assignments of credential-like identifiers to string literals of 8+ characters. Detects patterns like `password = "MyS3cr3t!"`, `API_KEY = "sk-1234..."`, `secret: "abc123xyz"`.',
		},
		remediation:
			'Remove all hardcoded secrets from source code and move them to a secrets management system (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). Use environment variables for runtime injection, ensuring they are never committed. Rotate all exposed secrets immediately. Add secret-scanning tools (git-secrets, trufflehog) to the CI/CD pipeline.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-020',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Use of Weak Cryptographic Hash Function (MD5)',
		description:
			'The codebase uses the MD5 hash algorithm which is cryptographically broken and unsuitable for password hashing, data integrity verification, or digital signatures. MD5 is vulnerable to collision attacks, making it unsuitable for any security-sensitive purpose.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'c', 'cpp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:MD5|md5|createHash\\s*\\(\\s*[\'"]md5[\'"]|hashlib\\.md5|MessageDigest\\.getInstance\\s*\\(\\s*[\'"]MD5[\'"]|crypto/md5)',
			flags: 'i',
			explanation:
				'Matches MD5 hash function usage across multiple languages and cryptographic libraries. Detects direct function calls and library-based usage patterns.',
		},
		remediation:
			'Replace MD5 with a secure algorithm: use SHA-256 or SHA-3 for integrity checks; use bcrypt, scrypt, Argon2, or PBKDF2 for password hashing. Never use MD5 for security-sensitive operations.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final',
		],
	},

	{
		id: 'cc5-021',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Use of Weak Cryptographic Hash Function (SHA-1)',
		description:
			'The codebase uses the SHA-1 hash algorithm which is no longer considered secure. SHA-1 is vulnerable to collision attacks (demonstrated by the SHAttered attack) and has been deprecated by NIST. It must not be used for certificate signing, code signing, or any security-critical hashing.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:SHA1|sha1|createHash\\s*\\(\\s*[\'"]sha1[\'"]|hashlib\\.sha1|MessageDigest\\.getInstance\\s*\\(\\s*[\'"]SHA-1[\'"]|crypto/sha1)',
			flags: 'i',
			explanation:
				'Matches SHA-1 usage across multiple languages and cryptographic libraries. Detects direct function calls and library method calls with the SHA-1 algorithm identifier.',
		},
		remediation:
			'Migrate from SHA-1 to SHA-256 or SHA-3. For HMAC operations use HMAC-SHA256. For digital signatures and TLS certificates ensure SHA-256 or stronger is specified. Update any existing SHA-1 certificates or checksums.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final',
			'https://shattered.io',
		],
	},

	{
		id: 'cc5-022',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Use of DES or Triple-DES Symmetric Encryption',
		description:
			'The codebase uses DES or Triple-DES (3DES/TDEA) for symmetric encryption. DES has a 56-bit key size that is trivially brute-forced. Triple-DES is deprecated by NIST due to the Sweet32 birthday attack and its small 64-bit block size.',
		severity: 'high',
		languages: ['java', 'python', 'csharp', 'php', 'ruby', 'typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:DESede|TripleDES|3DES|DES3|Cipher\\.getInstance\\s*\\(\\s*[\'"]DES)',
			flags: 'i',
			explanation:
				'Matches DES and Triple-DES cipher usage in cryptographic API calls. Detects patterns like Cipher.getInstance("DESede/CBC/PKCS5Padding") and DES3 references.',
		},
		remediation:
			'Replace DES/3DES with AES-256-GCM for symmetric encryption. AES-GCM provides both confidentiality and integrity (authenticated encryption). Migrate existing encrypted data by decrypting with the old algorithm and re-encrypting with AES-256-GCM.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc5-023',
		criteria: 'CC5.2',
		category: 'security',
		title: 'AES ECB Mode Usage',
		description:
			'The codebase uses AES in ECB (Electronic Codebook) mode. ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, revealing data patterns and making it unsuitable for encrypting more than one block even with a strong key.',
		severity: 'high',
		languages: ['java', 'python', 'csharp', 'php', 'ruby', 'typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:AES/ECB|ECBMode|createCipheriv\\s*\\(\\s*[\'"]aes-[0-9]+-ecb)',
			flags: 'i',
			explanation:
				'Matches AES encryption configured to use ECB mode. Detects patterns like Cipher.getInstance("AES/ECB/PKCS5Padding") and createCipheriv("aes-256-ecb").',
		},
		remediation:
			'Replace AES-ECB with AES-GCM (preferred) or AES-CBC with a random IV and separate HMAC. AES-GCM provides authenticated encryption which detects ciphertext tampering. Generate a fresh random IV for every encryption operation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-38a/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc5-024',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Cryptographically Weak Random Number Generation',
		description:
			'Security-sensitive operations (token generation, key generation, nonce creation) use non-cryptographically-secure random number generators such as Math.random(), rand(), random.random(), or java.util.Random. These are predictable and must not be used for security purposes.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'php', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:Math\\.random\\(\\)|rand\\(\\)|random\\.random\\(\\)|mt_rand\\(\\)|Kernel\\.rand)',
			flags: 'i',
			explanation:
				'Matches usage of non-cryptographic random number generators. Detects Math.random(), rand(), random.random(), PHP mt_rand(), and Ruby Kernel.rand.',
		},
		remediation:
			'Use cryptographically secure random number generators for all security-sensitive operations: `crypto.randomBytes()` in Node.js, `secrets.token_bytes()` in Python, `SecureRandom` in Java, `openssl_random_pseudo_bytes()` in PHP with the strong flag.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
			'https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final',
		],
	},

	{
		id: 'cc5-025',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Cookie Missing HttpOnly Flag',
		description:
			'Session or authentication cookies are set without the HttpOnly flag. Without this flag, JavaScript running in the page can read the cookie, allowing XSS attacks to steal session tokens and impersonate users.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'res\\.cookie\\s*\\([^)]+\\{[^}]*\\}\\s*\\)(?![\\s\\S]{0,50}httpOnly\\s*:\\s*true)',
			flags: 'i',
			explanation:
				'Matches cookie-setting operations where the options object does not include httpOnly: true. Indicates the HttpOnly flag is missing from cookie configuration.',
		},
		remediation:
			'Set the HttpOnly flag on all session and authentication cookies. In Express: `res.cookie("session", value, { httpOnly: true, secure: true, sameSite: "strict" })`. This prevents JavaScript access to the cookie value.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/HttpOnly',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies',
		],
	},

	{
		id: 'cc5-026',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Cookie Missing Secure Flag',
		description:
			'Authentication or session cookies are set without the Secure flag. Without this flag, cookies may be transmitted over unencrypted HTTP connections, exposing them to network eavesdropping and man-in-the-middle attacks.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'Set-Cookie:[^\\r\\n]*(?!;\\s*Secure)',
			flags: 'i',
			explanation:
				'Matches Set-Cookie headers that do not include the Secure attribute. Cookies without the Secure flag can be transmitted over plain HTTP connections.',
		},
		remediation:
			'Always set the Secure flag on all cookies that contain sensitive data. In Express: `{ secure: process.env.NODE_ENV === "production" }`. Enforce HTTPS for all production traffic so the Secure flag is always active.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/controls/SecureCookieAttribute',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies',
		],
	},

	{
		id: 'cc5-027',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Cookie Missing SameSite Attribute',
		description:
			'Session cookies are set without the SameSite attribute. Without SameSite, cookies are sent with cross-site requests, making CSRF attacks more likely. The SameSite attribute restricts when cookies are sent to same-site or same-origin requests.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: 'sameSite|SameSite',
			flags: 'i',
			explanation:
				'Detects the absence of SameSite in cookie configuration. If no SameSite attribute is set, cookies may be sent with cross-site requests, enabling CSRF attacks.',
		},
		remediation:
			'Add SameSite=Strict or SameSite=Lax to all session and authentication cookies. In Express: `res.cookie("session", value, { sameSite: "strict" })`. Use SameSite=Strict for highest security.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_attribute',
			'https://owasp.org/www-community/SameSite',
		],
	},

	{
		id: 'cc5-028',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Insecure TLS/SSL Protocol Version',
		description:
			'The application explicitly configures TLS 1.0 or TLS 1.1 as acceptable protocol versions. These versions have known vulnerabilities (BEAST, POODLE) and have been deprecated by RFC 8996. Only TLS 1.2 and TLS 1.3 should be used.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: '(?:TLSv1\\.0|TLSv1\\.1|SSLv2|SSLv3|TLS1_0|TLS1_1|minVersion\\s*:\\s*[\'"]TLSv1[\'"])',
			flags: 'i',
			explanation:
				'Matches explicit configuration of deprecated TLS/SSL protocol versions. Detects references to TLSv1.0, TLSv1.1, SSLv2, SSLv3 in TLS configuration parameters.',
		},
		remediation:
			'Configure your TLS stack to accept only TLS 1.2 and TLS 1.3. In Node.js set `minVersion: "TLSv1.2"` in TLS/HTTPS server options. Update nginx/Apache configurations to disable TLSv1 and TLSv1.1.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.rfc-editor.org/rfc/rfc8996',
			'https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final',
		],
	},

	{
		id: 'cc5-029',
		criteria: 'CC5.2',
		category: 'security',
		title: 'TLS Certificate Validation Disabled',
		description:
			'TLS certificate validation is explicitly disabled in HTTP client configuration. This allows the application to connect to servers with invalid, expired, or self-signed certificates, making it vulnerable to man-in-the-middle attacks where traffic can be intercepted and decrypted.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:rejectUnauthorized\\s*:\\s*false|verify\\s*=\\s*False|InsecureSkipVerify\\s*:\\s*true|ssl\\.CERT_NONE)',
			flags: 'i',
			explanation:
				'Matches explicit disabling of TLS certificate validation in various languages and HTTP client libraries. Detects patterns like rejectUnauthorized: false, InsecureSkipVerify: true, and verify=False.',
		},
		remediation:
			'Re-enable TLS certificate validation by removing the insecure option. If connecting to internal services with self-signed certificates, configure a custom CA bundle rather than disabling validation. Never disable certificate validation in production.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication',
			'https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final',
		],
	},

	{
		id: 'cc5-030',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Insecure Deserialization of User Input',
		description:
			'The application deserializes user-controlled data using unsafe deserialization functions without integrity verification. Insecure deserialization can lead to remote code execution, privilege escalation, and denial of service attacks.',
		severity: 'critical',
		languages: ['python', 'java', 'ruby', 'php', 'javascript', 'typescript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:pickle\\.loads|yaml\\.load\\s*\\([^,)]+\\)|Marshal\\.load|ObjectInputStream|unserialize\\s*\\(\\$_)',
			flags: 'i',
			explanation:
				'Matches unsafe deserialization function calls that process user-controlled data. Detects pickle.loads, unsafe yaml.load without SafeLoader, Java ObjectInputStream, and PHP unserialize with superglobals.',
		},
		remediation:
			'Use safe serialization formats (JSON) instead of native object serialization. For YAML, use SafeLoader: `yaml.safe_load()`. Sign serialized data with HMAC before deserializing to verify integrity. Never deserialize data from untrusted sources using native serialization.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
			'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-031',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Prototype Pollution Vulnerability',
		description:
			'Object merge, deep-clone, or property assignment operations use user-controlled keys without filtering `__proto__`, `constructor`, or `prototype` keys. Prototype pollution can corrupt the global Object prototype, leading to unexpected behavior or logic bypasses.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:merge|deepMerge|assign|extend|clone)\\s*\\([^)]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Matches object merge and deep-clone operations that use request-derived data as input without prototype pollution protection.',
		},
		remediation:
			'Filter prototype-polluting keys before merging: reject any key equal to `__proto__`, `constructor`, or `prototype`. Use `Object.create(null)` for objects used as maps. Use a hardened deep-merge library with built-in prototype pollution protection.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://learn.snyk.io/lesson/prototype-pollution/',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc5-032',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Regular Expression Denial of Service (ReDoS)',
		description:
			'User-controlled input is used with regular expressions that may contain catastrophic backtracking patterns. A ReDoS attack can cause the regex engine to take exponential time on crafted input, consuming all CPU and causing denial of service.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'new RegExp\\s*\\([^)]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Matches dynamically constructed regular expressions where the pattern itself is user-controlled. User input as the regex pattern is especially dangerous for ReDoS.',
		},
		remediation:
			'Never construct regular expression patterns from user input. Apply a timeout to regex operations on user-controlled strings. Use a ReDoS-safe library or a regex linter to audit existing patterns. Validate the complexity of regular expressions used for parsing user input.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc5-033',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Empty Catch Block (Swallowed Exception)',
		description:
			'Application catch blocks silently swallow exceptions without logging error details. Without error logging, security-relevant failures (authentication errors, authorization denials, input validation failures) go unrecorded, making incident detection and forensic investigation impossible.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'catch\\s*\\([^)]*\\)\\s*\\{\\s*(?://[^\\n]*\\n\\s*)?\\}|except\\s+(?:\\w+\\s+as\\s+\\w+)?\\s*:\\s*\\n\\s*pass\\s*$',
			flags: 'im',
			explanation:
				'Matches empty catch blocks and Python except-pass patterns. These represent swallowed exceptions where errors are silently ignored without any logging or handling.',
		},
		remediation:
			'Log all caught exceptions with sufficient context: error type, message, stack trace, and relevant request context. Use a structured logging library. Classify errors by severity and ensure security-relevant errors trigger alerts.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging_%2526_Monitoring',
			'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-034',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Stack Trace Exposed in HTTP Response',
		description:
			'Application error handlers return stack traces or detailed internal error information to HTTP clients. Stack traces reveal internal implementation details (file paths, library versions, class names) that attackers can use to craft targeted attacks.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:res\\.(?:json|send)\\s*\\([^)]*(?:err\\.stack|error\\.stack|e\\.stack))|stack\\s*:\\s*(?:err|error|e)\\.stack',
			flags: 'i',
			explanation:
				'Matches HTTP response calls that include error stack traces. Detects patterns like res.json({ stack: err.stack }) where internal stack traces are returned to clients.',
		},
		remediation:
			'Never return stack traces or internal error details to API clients. Create a global error handler that maps internal errors to user-safe error messages. Log the full error details server-side with a correlation ID. Return only the correlation ID to the client.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
			'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-035',
		criteria: 'CC5.2',
		category: 'security',
		title: 'Debug Mode Enabled in Application Configuration',
		description:
			'Application or framework debug mode is explicitly enabled in configuration. Debug mode typically exposes detailed error messages, internal state, configuration values, and interactive consoles that are invaluable to attackers but must never be accessible in production.',
		severity: 'critical',
		languages: ['python', 'ruby', 'php', 'typescript', 'javascript', 'java'],
		targets: ['config', 'source'],
		pattern: {
			type: 'regex',
			value: '(?:DEBUG\\s*=\\s*True|debug\\s*:\\s*true|app\\.debug\\s*=\\s*True|config\\.debug\\s*=\\s*true|DEBUG_MODE\\s*=\\s*1|FLASK_DEBUG\\s*=\\s*1)',
			flags: 'i',
			explanation:
				'Matches debug mode flags set to truthy values in application configuration and source code. Detects Django DEBUG=True, Express debug: true, Flask app.debug=True, and similar patterns.',
		},
		remediation:
			'Disable debug mode in all production configurations. Manage debug settings via environment variables (`DEBUG=false` or unset). Ensure your CI/CD pipeline validates that debug mode is disabled before deploying to production.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://12factor.net/config',
		],
	},

	// ── CC5.3 – Deployment Controls ──────────────────────────────────────────────

	{
		id: 'cc5-036',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Docker Container Running as Root User',
		description:
			'Dockerfile does not specify a non-root USER directive, meaning the container runs as root by default. If the container is compromised, the attacker has root privileges within the container and may be able to escape to the host system.',
		severity: 'high',
		languages: ['any'],
		targets: ['dockerfile'],
		pattern: {
			type: 'absence',
			value: 'USER\\s+(?!root|0\\s)[a-zA-Z0-9_-]+',
			flags: 'im',
			explanation:
				'Detects the absence of a non-root USER directive in a Dockerfile. If no USER instruction is present (or only USER root/0 is used), the container runs as root.',
		},
		remediation:
			'Add a USER directive in your Dockerfile to run the application as a non-root user. Create a dedicated application user: `RUN addgroup -S appgroup && adduser -S appuser -G appgroup` then `USER appuser`. Ensure the application files are owned by this user.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-037',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Docker Container Running in Privileged Mode',
		description:
			'Docker container or Kubernetes pod is configured with privileged mode enabled. Privileged containers have nearly unrestricted access to the host system, including all devices and kernel capabilities, effectively negating container isolation.',
		severity: 'critical',
		languages: ['any'],
		targets: ['dockerfile', 'kubernetes', 'iac'],
		pattern: {
			type: 'regex',
			value: 'privileged\\s*:\\s*true|--privileged',
			flags: 'i',
			explanation:
				'Matches privileged mode configuration in Dockerfiles, Docker Compose, and Kubernetes manifests. Detects privileged: true in security contexts and --privileged in run commands.',
		},
		remediation:
			'Remove privileged mode from all container configurations. If specific Linux capabilities are required, grant only those capabilities explicitly using `capabilities.add` rather than enabling full privileged mode.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://kubernetes.io/docs/concepts/security/pod-security-standards/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-038',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Missing Container Resource Limits',
		description:
			'Kubernetes pod or container specification does not define CPU and memory limits. Without resource limits, a single container can consume all cluster resources, causing denial-of-service for other services and making the system unstable.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'absence',
			value: 'limits:\\s*\\n\\s+cpu:|limits:\\s*\\n\\s+memory:',
			flags: 'im',
			explanation:
				'Detects the absence of resource limits in Kubernetes container specifications. If no resources.limits block is found, the container can consume unlimited CPU and memory.',
		},
		remediation:
			'Define both CPU and memory requests and limits for all containers. Set requests to the expected normal usage and limits to the maximum acceptable usage. Implement LimitRange objects to enforce default resource limits across namespaces.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-039',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Sensitive Port Exposed in Dockerfile',
		description:
			'Dockerfile exposes well-known sensitive ports such as SSH (22), database ports (3306, 5432, 27017, 6379), or management interfaces. Exposing these ports increases the attack surface and may allow direct access to sensitive services.',
		severity: 'high',
		languages: ['any'],
		targets: ['dockerfile'],
		pattern: {
			type: 'regex',
			value: 'EXPOSE\\s+(?:22|23|21|3306|5432|27017|6379|6380|1433|1521|9200|9300)',
			explanation:
				'Matches EXPOSE directives for well-known sensitive ports: SSH (22), Telnet (23), FTP (21), MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379/6380), MSSQL (1433), Oracle (1521), Elasticsearch (9200/9300).',
		},
		remediation:
			'Remove EXPOSE directives for sensitive ports from Dockerfiles. Database ports, SSH, and management interfaces should not be exposed in container images. Use internal Kubernetes services for database connectivity.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-040',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Missing Kubernetes Network Policy',
		description:
			'Kubernetes namespace does not define NetworkPolicy resources, allowing unrestricted pod-to-pod communication. Without network policies, a compromised pod can make network connections to any other pod in the cluster, facilitating lateral movement.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'absence',
			value: 'kind:\\s*NetworkPolicy',
			flags: 'i',
			explanation:
				'Detects the absence of NetworkPolicy resources in Kubernetes manifests. If no NetworkPolicy kind is defined, all pods can communicate with each other without restriction.',
		},
		remediation:
			'Define Kubernetes NetworkPolicy resources to implement least-privilege network access. Start with a default-deny-all policy for both ingress and egress, then explicitly allow required communication paths.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://kubernetes.io/docs/concepts/services-networking/network-policies/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-041',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Secrets Stored as Plain Environment Variables in Kubernetes',
		description:
			'Kubernetes pod specifications define sensitive values (passwords, API keys, tokens) as plain environment variables in the manifest rather than referencing Kubernetes Secrets. Plain environment variables in manifests are stored in etcd without encryption.',
		severity: 'critical',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'regex',
			value: '- name:\\s*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|PRIVATE)[_A-Z]*\\s*\\n\\s+value:\\s+[\'"]?[^$\\s\'"][^\\n]+',
			flags: 'im',
			explanation:
				'Matches Kubernetes manifest env entries where variables with sensitive names (PASSWORD, SECRET, TOKEN, KEY) have hardcoded values instead of valueFrom.secretKeyRef references.',
		},
		remediation:
			'Store sensitive values in Kubernetes Secrets and reference them using `valueFrom.secretKeyRef`. Encrypt Kubernetes Secrets at rest using KMS encryption. Consider using external secrets operators (External Secrets Operator, Vault Agent) that fetch secrets from dedicated secret stores.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://kubernetes.io/docs/concepts/configuration/secret/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-042',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Missing Pod Security Context',
		description:
			'Kubernetes pod or container specification does not define a securityContext. Without security context settings, containers may run with excessive Linux capabilities, write access to the root filesystem, or as root users, all of which increase blast radius.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'absence',
			value: 'securityContext:',
			flags: 'i',
			explanation:
				'Detects the absence of a securityContext block in Kubernetes pod or container specs. Missing security context means default permissive settings are used.',
		},
		remediation:
			'Add a securityContext to all pod and container specifications with: `runAsNonRoot: true`, `runAsUser: <non-zero-uid>`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, and `capabilities.drop: ["ALL"]`.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-043',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Overly Permissive Kubernetes ClusterRoleBinding to cluster-admin',
		description:
			'A Kubernetes ClusterRoleBinding grants the `cluster-admin` role to a service account or user. This provides unrestricted access to all resources in all namespaces, violating the principle of least privilege.',
		severity: 'critical',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'regex',
			value: 'kind:\\s*ClusterRoleBinding[\\s\\S]{0,500}?name:\\s*cluster-admin',
			flags: 'im',
			explanation:
				'Matches ClusterRoleBinding resources that bind to the cluster-admin ClusterRole, granting full administrative access to the entire cluster.',
		},
		remediation:
			'Replace cluster-admin bindings with least-privilege roles. Audit all ClusterRoleBindings and replace with namespace-scoped RoleBindings where possible. Create custom ClusterRoles with only the specific permissions required.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://kubernetes.io/docs/reference/access-authn-authz/rbac/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-044',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Missing Security Scanning Step in CI/CD Pipeline',
		description:
			'The CI/CD pipeline configuration does not include a security scanning step (SAST, SCA, container scanning, or secrets detection). Without automated security scanning, vulnerabilities and exposed secrets may be deployed to production undetected.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value: 'trivy|snyk|sonarqube|semgrep|bandit|gitleaks|trufflehog|codeql|checkmarx|npm audit|yarn audit|safety|gosec',
			flags: 'i',
			explanation:
				'Detects the absence of any security scanning tool reference in CI/CD pipeline configuration. If no security scanner is configured, the pipeline provides no automated vulnerability detection.',
		},
		remediation:
			'Integrate security scanning into your CI/CD pipeline: add SAST (Semgrep, CodeQL), SCA (Snyk, npm audit), container scanning (Trivy), and secrets detection (gitleaks). Configure pipeline gates that fail builds when critical vulnerabilities are detected.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-devsecops-guideline/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc5-045',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Overly Permissive IAM Policy Using Wildcard Actions',
		description:
			'IAM policy or role definition uses wildcard action (`*`) or resource (`*`) permissions. Wildcard permissions grant far more access than necessary, violating the principle of least privilege.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac', 'config'],
		pattern: {
			type: 'regex',
			value: '"Action"\\s*:\\s*"\\*"|\'Action\'\\s*:\\s*\'\\*\'|action\\s*=\\s*"\\*"',
			flags: 'im',
			explanation:
				'Matches IAM policy definitions that use wildcard (*) as the Action value, granting all permissions. Detects patterns in AWS CloudFormation, Terraform, and raw IAM policy JSON.',
		},
		remediation:
			'Replace wildcard IAM actions with the minimum specific actions required. Use IAM Access Analyzer to identify overly permissive policies and generate least-privilege replacements. Review and tighten IAM policies quarterly.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-046',
		criteria: 'CC5.3',
		category: 'security',
		title: 'S3 Bucket Public Access Not Blocked',
		description:
			'Terraform or CloudFormation configuration defines an S3 bucket without explicitly blocking public access. By default or through misconfiguration, S3 buckets can become publicly accessible, potentially exposing sensitive data to the internet.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac'],
		pattern: {
			type: 'regex',
			value: 'BlockPublicAcls\\s*:\\s*false|RestrictPublicBuckets\\s*:\\s*false|block_public_acls\\s*=\\s*false',
			flags: 'im',
			explanation:
				'Matches S3 public access block settings that are explicitly set to false. This indicates the bucket may be publicly accessible.',
		},
		remediation:
			'Set all four S3 Block Public Access settings to true for all buckets. Enable S3 Block Public Access at the account level as a preventive control. Use AWS Config rules to detect and remediate public buckets.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-047',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Database Encryption at Rest Not Configured',
		description:
			'Database resource definition (RDS, Cloud SQL) does not enable storage encryption. Data at rest in an unencrypted database is exposed if the underlying storage media is accessed, stolen, or if a cloud provider misconfiguration occurs.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac'],
		pattern: {
			type: 'regex',
			value: 'resource\\s+"aws_db_instance"[^}]*\\}(?![\\s\\S]{0,500}storage_encrypted\\s*=\\s*true)',
			flags: 'im',
			explanation:
				'Matches AWS RDS database instance resource definitions that do not include storage_encrypted = true.',
		},
		remediation:
			'Enable storage encryption on all database instances using managed key services (AWS KMS, Cloud KMS). For AWS RDS set `storage_encrypted = true` and specify a `kms_key_id`. Apply encryption-at-rest requirements via AWS Config rules.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-111/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-048',
		criteria: 'CC5.3',
		category: 'security',
		title: 'VPC Security Group Allows Unrestricted Inbound Access',
		description:
			'A security group rule allows inbound traffic from `0.0.0.0/0` (all IPv4) on sensitive ports. This exposes resources directly to the internet, violating network perimeter controls.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac'],
		pattern: {
			type: 'regex',
			value: 'cidr_blocks\\s*=\\s*\\["0\\.0\\.0\\.0/0"\\]|CidrIp:\\s*0\\.0\\.0\\.0/0',
			flags: 'im',
			explanation:
				'Matches security group ingress rules that allow traffic from the entire internet (0.0.0.0/0).',
		},
		remediation:
			'Replace 0.0.0.0/0 inbound rules with specific CIDR ranges, security group IDs, or prefix lists for the sources that actually need access. Use a bastion host or VPN for administrative access.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-049',
		criteria: 'CC5.3',
		category: 'security',
		title: 'CloudTrail Logging Not Configured',
		description:
			'AWS CloudTrail is not configured in infrastructure definitions. Without CloudTrail, API calls to AWS services are not logged, making it impossible to detect unauthorized access or investigate security incidents.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac', 'config'],
		pattern: {
			type: 'absence',
			value: 'aws_cloudtrail|CloudTrail|cloudtrail|is_multi_region_trail',
			flags: 'i',
			explanation:
				'Detects the absence of CloudTrail configuration in infrastructure code. If no CloudTrail resource is present, AWS API activity is not being logged.',
		},
		remediation:
			'Enable AWS CloudTrail in all regions with multi-region trail enabled, log file validation, and S3 access logging. Integrate CloudTrail with CloudWatch Logs for real-time alerting on suspicious activity.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-050',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Missing Container Image Pinning to Digest',
		description:
			'Dockerfile or Kubernetes manifest references container images by mutable tag rather than by immutable digest. Tags can be updated to point to different, potentially malicious images without notice.',
		severity: 'medium',
		languages: ['any'],
		targets: ['dockerfile', 'kubernetes'],
		pattern: {
			type: 'regex',
			value: 'FROM\\s+[a-zA-Z0-9._/-]+:latest|image:\\s+[a-zA-Z0-9._/-]+:latest',
			flags: 'i',
			explanation:
				'Matches FROM directives and image: fields that reference the :latest tag. The latest tag is mutable and can change between builds.',
		},
		remediation:
			'Pin container images to their SHA256 digest for production deployments. Use tools like Renovate or Dependabot to automatically update pinned digests. Implement image signing and verification using Cosign.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-051',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Secrets Hardcoded in CI/CD Pipeline Configuration',
		description:
			'CI/CD pipeline configuration files contain hardcoded secrets, passwords, or API keys in environment variable definitions or script commands. Pipeline configuration files stored in source control may be visible to all repository contributors.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'regex',
			value: '(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\\s*:\\s*[\'"]?[A-Za-z0-9+/]{20,}={0,2}[\'"]?',
			flags: 'im',
			explanation:
				'Matches CI/CD pipeline environment variable assignments where sensitive variable names are assigned long alphanumeric values that look like hardcoded secrets.',
		},
		remediation:
			'Remove all hardcoded secrets from CI/CD configuration files. Use your platform\'s secrets management (GitHub Actions secrets, GitLab CI/CD variables) to inject secrets at runtime. Rotate any exposed secrets immediately.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
			'https://owasp.org/www-project-devsecobs-guideline/',
		],
	},

	{
		id: 'cc5-052',
		criteria: 'CC5.3',
		category: 'security',
		title: 'npm Package Lock File Missing',
		description:
			'A Node.js project does not have a dependency lock file committed to the repository. Without a lock file, `npm install` resolves the latest compatible versions which may install vulnerable or compromised packages compared to what was tested.',
		severity: 'medium',
		languages: ['typescript', 'javascript'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: 'package-lock\\.json|yarn\\.lock|pnpm-lock\\.yaml',
			flags: 'i',
			explanation:
				'Detects the absence of a dependency lock file in Node.js projects. Lock files ensure reproducible installs and prevent dependency confusion attacks.',
		},
		remediation:
			'Commit the package-lock.json or yarn.lock file to the repository. Never add lock files to .gitignore. Run `npm ci` instead of `npm install` in CI/CD pipelines. Enable `npm audit` in the pipeline to detect known vulnerabilities.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://docs.npmjs.com/cli/v10/commands/npm-ci',
		],
	},

	{
		id: 'cc5-053',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Logging Sensitive Personal Data',
		description:
			'Application log statements include fields that may contain personal identifiable information (PII) such as passwords, credit card numbers, or social security numbers. Logging PII creates compliance violations and expands breach impact if logs are compromised.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:log|logger|console)\\s*\\.(?:info|debug|warn|error|log)\\s*\\([^)]*(?:password|ssn|social.?security|credit.?card|cvv)',
			flags: 'i',
			explanation:
				'Matches logging calls that include sensitive field names in their arguments. Detects logging of passwords, SSNs, credit card numbers, and similar PII fields.',
		},
		remediation:
			'Implement a log sanitization layer that strips or masks sensitive fields before logging. Use structured logging with field-level redaction for known sensitive keys. Add automated PII detection to your log pipeline.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc5-054',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Automated Dependency Vulnerability Scanning Not Configured',
		description:
			'The project does not configure automated dependency vulnerability scanning. Without automated scanning, vulnerable dependency versions may persist undetected, introducing known exploitable vulnerabilities into production.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['config'],
		pattern: {
			type: 'absence',
			value: 'dependabot\\.yml|renovate\\.json|snyk|npm audit|bundle-audit|safety check|govulncheck',
			flags: 'i',
			explanation:
				'Detects the absence of automated dependency vulnerability scanning configuration. Without this, vulnerable dependency versions may persist undetected.',
		},
		remediation:
			'Configure automated dependency vulnerability scanning: use Dependabot, Renovate, or Snyk to automatically create PRs for vulnerable dependency updates. Add `npm audit --audit-level=high` or equivalent to the CI pipeline.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-dependency-check/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc5-055',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Missing Read-Only Root Filesystem in Container',
		description:
			'Dockerfile or Kubernetes container specification does not configure a read-only root filesystem. Without this control, malware or an attacker who gains code execution can write to the container filesystem, potentially modifying application binaries or writing backdoors.',
		severity: 'medium',
		languages: ['any'],
		targets: ['dockerfile', 'kubernetes'],
		pattern: {
			type: 'absence',
			value: 'readOnlyRootFilesystem:\\s*true|--read-only',
			flags: 'i',
			explanation:
				'Detects the absence of read-only root filesystem configuration in container security contexts. If readOnlyRootFilesystem is not set to true, containers can write to any path in their filesystem.',
		},
		remediation:
			'Set `readOnlyRootFilesystem: true` in Kubernetes container security contexts. Mount writable volumes only for paths that genuinely need write access (temp directories, application data). Test the application to identify all paths requiring write access before enabling.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-056',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Terraform State Not Encrypted',
		description:
			'Terraform S3 backend configuration does not enable encryption for remote state storage. Terraform state files may contain sensitive data including resource IDs, connection strings, and occasionally plaintext secrets.',
		severity: 'high',
		languages: ['any'],
		targets: ['iac'],
		pattern: {
			type: 'regex',
			value: 'backend\\s+"s3"[^}]*encrypt\\s*=\\s*false|backend\\s+"s3"(?![^}]*encrypt\\s*=\\s*true)',
			flags: 'im',
			explanation:
				'Matches Terraform S3 backend configurations that either explicitly disable encryption or omit the encrypt setting entirely.',
		},
		remediation:
			'Enable encryption for Terraform state storage: for S3 backends add `encrypt = true` and configure a KMS key with `kms_key_id`. Enable versioning on the S3 bucket. Use Terraform Cloud for managed state storage with built-in encryption.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.terraform.io/language/settings/backends/s3',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc5-057',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Missing Signed Commits Enforcement',
		description:
			'The CI/CD pipeline or repository branch protection rules do not enforce commit signing. Without signed commits, it is impossible to verify the identity of the author, and pipeline artifacts cannot be traced back to verified developer actions.',
		severity: 'medium',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value: 'required_signatures|require_signed_commits|commit\\.gpgsign|signingKey|COSIGN|sigstore',
			flags: 'i',
			explanation:
				'Detects the absence of commit signing requirements in CI/CD configuration or repository settings. Without signing enforcement, commit author identity cannot be cryptographically verified.',
		},
		remediation:
			'Enable required commit signing through branch protection rules. Configure developer machines with GPG signing: `git config commit.gpgsign true`. Use Sigstore/Cosign for signing container images and release artifacts.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://docs.github.com/en/authentication/managing-commit-signature-verification',
			'https://www.sigstore.dev',
		],
	},

	{
		id: 'cc5-058',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Missing Subresource Integrity on External Scripts',
		description:
			'HTML pages load external JavaScript or CSS resources from CDNs without Subresource Integrity (SRI) hashes. Without SRI, if the CDN is compromised the malicious code will execute in users\' browsers without detection.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '<script[^>]+src=["\']https?://(?!localhost)[^"\']+["\'][^>]*>(?![^<]*integrity=)',
			flags: 'i',
			explanation:
				'Matches external script tags loading from non-local URLs that do not include an integrity attribute. Scripts without SRI can be tampered with by the CDN or an attacker.',
		},
		remediation:
			'Add Subresource Integrity (SRI) hashes to all external script and stylesheet references. Generate the hash using `openssl dgst -sha384 -binary file.js | openssl base64 -A`. Include both the integrity attribute and `crossorigin="anonymous"`.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
			'https://www.w3.org/TR/SRI/',
		],
	},

	{
		id: 'cc5-059',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Server-Side Request Forgery (SSRF) via User-Controlled URL',
		description:
			'The application makes HTTP requests to URLs that are constructed from user-supplied input without validation. An attacker can supply internal URLs to access cloud metadata services, internal APIs, or other resources not intended for external access.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:fetch|axios\\.get|axios\\.post|requests\\.get|requests\\.post|http\\.Get|http\\.Post|curl_exec|Net::HTTP\\.get)\\s*\\([^)]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Matches HTTP request functions whose URL argument includes request-derived variables. Detects patterns like `fetch(req.query.url)` or `requests.get(user_input)` that enable SSRF.',
		},
		remediation:
			'Validate and allowlist all user-supplied URLs before making HTTP requests. Parse the URL and check the hostname against an allowlist of permitted external domains. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x), localhost, and internal domains. Use a DNS-rebinding-safe HTTP client.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
			'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc5-060',
		criteria: 'CC5.3',
		category: 'security',
		title: 'Dynamic Code Execution with User Input (eval)',
		description:
			'The application passes user-controlled data to dynamic code execution functions (eval, Function constructor, exec). This can lead to arbitrary code execution, allowing attackers to run any code with the privileges of the application process.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:eval|new Function|exec|compile)\\s*\\([^)]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Matches eval, Function constructor, and exec calls whose argument includes request-derived variables. These patterns enable arbitrary code execution via user input.',
		},
		remediation:
			'Never pass user input to eval, new Function, or similar dynamic code execution functions. Use JSON.parse for data parsing, predefined function maps for dynamic behavior, or a sandbox runtime for intentional scripting capabilities. Perform a codebase-wide audit to identify and eliminate all eval usage.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval_Injection',
			'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
		],
	},
];
