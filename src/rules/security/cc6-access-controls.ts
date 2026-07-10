/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc6Rules: ISoc2Rule[] = [

	// ─── CC6.1 Logical Access Security (rules 001–015) ────────────────────────

	{
		id: 'cc6-001',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Hardcoded credentials in source code',
		description:
			'A password, secret key, or API token is assigned as a string literal directly in source code, exposing credentials to anyone with repository access.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\\s*(?:=|:)\\s*["\'][^"\'\\s]{4,}["\']',
			flags: 'i',
			explanation:
				'Matches assignment of non-empty string literals to variables whose names indicate credentials.',
		},
		remediation:
			'Remove credentials from source. Use environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or a .env file excluded from version control.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-002',
		criteria: 'CC6.1',
		category: 'security',
		title: 'TLS certificate validation disabled',
		description:
			'TLS/SSL certificate verification is explicitly disabled, exposing connections to man-in-the-middle attacks.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'go', 'java', 'ruby'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: '(?:verify\\s*=\\s*False|NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*["\']0["\']|InsecureSkipVerify\\s*:\\s*true|rejectUnauthorized\\s*:\\s*false|CURLOPT_SSL_VERIFYPEER\\s*,\\s*false)',
			flags: 'i',
			explanation:
				'Matches common patterns that disable TLS certificate validation across multiple languages and frameworks.',
		},
		remediation:
			'Always validate TLS certificates in production. Configure proper CA trust stores and never bypass certificate verification.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-003',
		criteria: 'CC6.1',
		category: 'security',
		title: 'JWT without expiration claim',
		description:
			'A JSON Web Token is created without an expiration (exp) claim, making the token valid indefinitely and increasing the attack surface if it is compromised.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'jwt\\.sign\\s*\\([^)]*\\)(?!.*expiresIn)(?!.*exp\\s*:)',
			flags: 'i',
			explanation:
				"Detects jwt.sign() calls that lack an expiresIn option or an explicit exp claim, indicating tokens that never expire.",
		},
		remediation:
			'Always set a short-lived expiration on JWTs (e.g., expiresIn: "15m"). Implement refresh-token rotation for long-lived sessions.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-004',
		criteria: 'CC6.1',
		category: 'security',
		title: 'JWT "none" algorithm accepted',
		description:
			'The application accepts the JWT "none" algorithm, allowing an attacker to forge tokens without a valid signature.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:algorithms?\\s*[=:]\\s*["\']none["\']|algorithm\\s*[=:]\\s*\\[?["\']none["\'])',
			flags: 'i',
			explanation:
				'Matches JWT library configuration that explicitly allows the "none" algorithm.',
		},
		remediation:
			'Whitelist only strong algorithms (RS256, ES256). Never include "none" in the allowed algorithm list. Validate the alg header against the whitelist on every request.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-005',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Weak session token generation using Math.random()',
		description:
			'Session identifiers or tokens are generated using Math.random(), which is not cryptographically secure and can be predicted by an attacker.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:session|token|secret|nonce|csrf)\\s*[=:].*Math\\.random\\s*\\(\\)',
			flags: 'i',
			explanation:
				'Detects assignment of Math.random() output to variables that represent session tokens or secrets.',
		},
		remediation:
			'Use a cryptographically secure random number generator: crypto.randomBytes() in Node.js, secrets.token_hex() in Python, or java.security.SecureRandom in Java.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-006',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Missing session invalidation on logout',
		description:
			'Logout handlers do not destroy or invalidate the server-side session, leaving sessions active after a user logs out.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:req\\.session\\.destroy|session\\.invalidate|session\\.clear|logout\\(\\)|revoke_token)',
			flags: 'i',
			explanation:
				'Flags logout route handlers that do not call a session-destruction or token-revocation function.',
		},
		remediation:
			'On logout, destroy the server-side session (req.session.destroy()), revoke any active refresh tokens, and set the session cookie to expire immediately.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-007',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Plain-text password storage',
		description:
			'User passwords are stored or compared without hashing, exposing all user credentials if the database is breached.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:password\\s*==\\s*|password\\s*===\\s*|user\\.password\\s*=\\s*req\\.body\\.password|INSERT.*password.*VALUES)',
			flags: 'i',
			explanation:
				'Detects direct password comparison or insertion without an intermediate hashing call.',
		},
		remediation:
			'Always hash passwords with a memory-hard algorithm (bcrypt, Argon2, or scrypt) before storage. Never compare raw passwords.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-008',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Weak password hashing (MD5 or SHA-1)',
		description:
			'Passwords are hashed with MD5 or SHA-1, which are fast cryptographic hash functions not suitable for password storage and vulnerable to brute-force attacks.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:md5|sha1|sha-1)\\s*\\(',
			flags: 'i',
			explanation:
				'Matches calls to MD5 or SHA-1 hash functions, which are inappropriate for password storage.',
		},
		remediation:
			'Replace MD5/SHA-1 with bcrypt (cost factor >= 12), Argon2id, or scrypt for password hashing. For data integrity, use SHA-256 or stronger.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-009',
		criteria: 'CC6.1',
		category: 'security',
		title: 'bcrypt with insufficient work factor',
		description:
			'bcrypt is called with a cost factor (rounds) below 12, making brute-force attacks significantly faster on modern hardware.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'bcrypt(?:js)?\\s*\\.(?:hash|genSalt)\\s*\\([^,)]*,\\s*([1-9]|10|11)(?:\\s*[,)])',
			explanation:
				'Matches bcrypt.hash() or bcrypt.genSalt() calls where the rounds argument is less than 12.',
		},
		remediation:
			'Set the bcrypt cost factor to at least 12 (ideally 14 for new systems). Re-hash existing passwords at login using the higher factor.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-010',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Missing MFA enforcement on privileged operations',
		description:
			'Administrative or high-value actions (password change, payment, privilege escalation) lack a second authentication factor check.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:mfa|totp|otp|two.factor|2fa|second.factor)',
			flags: 'i',
			explanation:
				'Flags privileged route handlers that contain no reference to MFA, TOTP, OTP, or two-factor verification.',
		},
		remediation:
			'Require MFA for all admin routes and sensitive operations. Integrate TOTP (RFC 6238) or a WebAuthn-based second factor and verify it server-side on every privileged action.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc6-011',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Authentication bypass via HTTP verb tampering',
		description:
			'The authentication middleware only checks specific HTTP methods (e.g., POST), allowing attackers to bypass authentication by using a different verb such as GET or PUT.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'if\\s*\\(\\s*req\\.method\\s*(?:===|==)\\s*["\'](?:POST|GET|PUT|DELETE)["\']\\s*\\)',
			flags: 'i',
			explanation:
				'Detects authentication guards conditional on a single HTTP method, which can be bypassed with other verbs.',
		},
		remediation:
			'Apply authentication middleware to all HTTP methods on protected routes. Do not make authentication conditional on the request method.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-012',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Session cookie missing HttpOnly flag',
		description:
			'Session cookies are set without the HttpOnly attribute, allowing JavaScript to read them and enabling session hijacking via XSS.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: 'Set-Cookie:[^\\n]*(?<!httponly)(?<!HttpOnly)\\r?\\n',
			flags: 'i',
			explanation:
				'Matches Set-Cookie headers that do not include the HttpOnly directive.',
		},
		remediation:
			'Set the HttpOnly flag on all session and authentication cookies. Also set Secure and SameSite=Strict or SameSite=Lax.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-013',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Session cookie missing Secure flag',
		description:
			'Session cookies are set without the Secure attribute, allowing them to be transmitted over unencrypted HTTP connections.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: 'res\\.cookie\\s*\\([^)]*\\{[^}]*(?<!secure\\s*:\\s*true)[^}]*\\}',
			flags: 'i',
			explanation:
				'Detects cookie-setting calls that lack the secure: true option in the options object.',
		},
		remediation:
			'Always set secure: true when setting session cookies in production. Use HSTS to enforce HTTPS site-wide.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-014',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Use of deprecated or broken crypto algorithm (DES/RC4)',
		description:
			'The code uses DES, 3DES, or RC4 encryption algorithms that are known to be cryptographically broken or weak.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:DES|3DES|RC4|TripleDES|DESede|Blowfish)(?:\\s*[/(\'"]|Algorithm)',
			flags: 'i',
			explanation:
				'Matches references to deprecated symmetric encryption algorithms.',
		},
		remediation:
			'Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption. Remove all usage of DES, 3DES, and RC4.',
		references: [
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-015',
		criteria: 'CC6.1',
		category: 'security',
		title: 'OAuth redirect_uri not validated',
		description:
			'The OAuth authorization endpoint accepts arbitrary redirect_uri values without validating them against a registered whitelist, enabling open-redirect and code-interception attacks.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:redirect_uri.*whitelist|allowedRedirectUris|validRedirectUri|redirect_uri.*includes|redirect_uri.*indexOf)',
			flags: 'i',
			explanation:
				'Flags OAuth callback handlers that extract redirect_uri from the request but perform no whitelist validation.',
		},
		remediation:
			'Validate the redirect_uri against a pre-registered whitelist for every authorization request. Reject requests with unregistered or wildcard URIs.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	// ─── CC6.2 Authentication Prior to Access (rules 016–025) ─────────────────

	{
		id: 'cc6-016',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Missing authorization header validation on API route',
		description:
			'An API endpoint reads or modifies data without verifying that an Authorization header is present and valid.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:req\\.headers\\[.authorization.\\]|req\\.headers\\.authorization|Bearer\\s|verifyToken|authenticate|isAuthenticated)',
			flags: 'i',
			explanation:
				'Flags route handlers that access request body or path params but do not check an authorization header.',
		},
		remediation:
			'Apply an authentication middleware (e.g., passport.authenticate, verifyJWT) to every protected route before any business logic runs.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-017',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Insecure direct object reference (IDOR)',
		description:
			'The application uses a user-supplied identifier to directly look up a database record without verifying ownership, allowing users to access other users\' data.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:findById|find_by_id|findOne|getById)\\s*\\(\\s*req\\.(?:params|query|body)\\.',
			flags: 'i',
			explanation:
				'Matches database lookup calls that pass user-controlled identifiers without an ownership filter.',
		},
		remediation:
			'Always scope data lookups to the authenticated user (e.g., WHERE id = ? AND user_id = current_user_id). Never trust user-supplied record IDs alone.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-018',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Missing role check before privileged action',
		description:
			'A route or function that performs an administrative or privileged action does not verify that the caller has the required role or permission.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:role\\s*===|hasRole|isAdmin|authorize|permission|can\\s*\\()',
			flags: 'i',
			explanation:
				'Flags admin/privileged route handlers that do not contain any role or permission check.',
		},
		remediation:
			'Add an authorization middleware or guard that checks the authenticated user\'s role before executing any privileged action.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-019',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Broken access control via mass assignment',
		description:
			'The application passes the entire request body directly to a model constructor or update method, enabling attackers to set protected fields such as isAdmin or role.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:new\\s+\\w+\\s*\\(\\s*req\\.body\\s*\\)|update\\s*\\(\\s*req\\.body\\s*\\)|create\\s*\\(\\s*req\\.body\\s*\\)|\\.save\\s*\\(\\s*req\\.body\\s*\\))',
			flags: 'i',
			explanation:
				'Detects model creation or update calls that use the raw request body as input without field filtering.',
		},
		remediation:
			'Whitelist allowed fields before passing data to the model layer. Use a DTO or validation schema to strip out protected attributes.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-020',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Privilege escalation via user-controlled role parameter',
		description:
			'The application accepts a role or isAdmin field from user-supplied input and stores or uses it without server-side authority verification.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'req\\.body\\.(?:role|isAdmin|admin|is_admin|permissions)\\b',
			flags: 'i',
			explanation:
				'Detects direct reads of role or admin fields from the request body, which are attacker-controlled.',
		},
		remediation:
			'Never derive a user\'s role or privilege level from client-supplied data. Read role information exclusively from the authenticated session or a trusted server-side store.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-021',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Unauthenticated GraphQL mutation',
		description:
			'A GraphQL mutation that modifies data is accessible without authentication, allowing anonymous callers to perform write operations.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:context\\.user|context\\.auth|isAuthenticated|requireAuth|@auth|authGuard)',
			flags: 'i',
			explanation:
				'Flags GraphQL mutation resolvers that do not check the request context for an authenticated user.',
		},
		remediation:
			'Apply an authentication directive or guard to all GraphQL mutations. Throw an AuthenticationError if context.user is absent.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-022',
		criteria: 'CC6.2',
		category: 'security',
		title: 'JWT signature not verified (verify skipped)',
		description:
			'The application decodes a JWT to extract claims without verifying the signature, allowing attackers to forge tokens with arbitrary payloads.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:jwt\\.decode|jwtDecode|base64\\.decode|atob)\\s*\\([^)]*\\)(?!.*jwt\\.verify)',
			flags: 'i',
			explanation:
				'Detects JWT decode calls not accompanied by a subsequent verify call, indicating the signature is never checked.',
		},
		remediation:
			'Always use jwt.verify() (not jwt.decode()) to validate the token signature before trusting any claim. Reject tokens with invalid or missing signatures.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-023',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Horizontal access control bypass via URL path manipulation',
		description:
			'Resource identifiers in URL path segments are used to access records without scoping the query to the authenticated user, enabling horizontal privilege escalation.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'router\\.(?:get|put|patch|delete)\\s*\\(["\'][^"\']*:(?:id|userId|accountId|documentId)',
			flags: 'i',
			explanation:
				'Matches route definitions with user-controlled path identifiers, which require an ownership check to prevent IDOR.',
		},
		remediation:
			'Add an ownership filter to every query: WHERE id = :id AND owner_id = :currentUserId. Return 403 (not 404) when ownership validation fails.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-024',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Authentication logic returns truthy on exception',
		description:
			'An authentication or authorization check catches exceptions and returns a truthy value or continues execution, potentially granting access on error.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'catch\\s*\\([^)]*\\)\\s*\\{[^}]*return\\s+true',
			flags: 'i',
			explanation:
				'Detects catch blocks that return true, which can grant access when an authentication function throws.',
		},
		remediation:
			'Authentication functions should deny access on any exception. Catch blocks in auth logic must return false or rethrow the error.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-025',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Unauthenticated WebSocket endpoint',
		description:
			'A WebSocket connection upgrade handler does not verify authentication before establishing the connection, allowing anonymous access to real-time data.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:verifyClient|authenticate|isAuthenticated|jwt\\.verify|session\\.user)',
			flags: 'i',
			explanation:
				'Flags WebSocket server setup (ws.Server, io.on("connection")) that lacks an authentication check in the upgrade or connection handler.',
		},
		remediation:
			'Validate authentication credentials (JWT, session cookie) in the WebSocket upgrade request before accepting the connection. Reject unauthenticated upgrade requests with HTTP 401.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	// ─── CC6.3 Role-Based Access Control (rules 026–035) ──────────────────────

	{
		id: 'cc6-026',
		criteria: 'CC6.3',
		category: 'security',
		title: 'IAM wildcard action permission (*)',
		description:
			'An IAM policy grants Action: "*" on one or more resources, giving the principal unrestricted access to all AWS services and actions.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac', 'config'],
		pattern: {
			type: 'regex',
			value: '"Action"\\s*:\\s*"\\*"',
			explanation:
				'Matches IAM policy documents that use a wildcard action, granting all permissions.',
		},
		remediation:
			'Replace wildcard actions with the minimum set of specific actions required (principle of least privilege). Use IAM Access Analyzer to identify and reduce overly permissive policies.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-027',
		criteria: 'CC6.3',
		category: 'security',
		title: 'IAM wildcard resource permission (*)',
		description:
			'An IAM policy applies actions to Resource: "*", giving the principal access to all resources of the affected service rather than a scoped set.',
		severity: 'high',
		languages: ['any'],
		targets: ['iac', 'config'],
		pattern: {
			type: 'regex',
			value: '"Resource"\\s*:\\s*"\\*"',
			explanation:
				'Matches IAM policy documents that scope to all resources using a wildcard.',
		},
		remediation:
			'Scope IAM resources to specific ARNs or ARN patterns. Avoid Resource: "*" except where explicitly required by an AWS service.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-028',
		criteria: 'CC6.3',
		category: 'security',
		title: 'Default admin role assigned at user creation',
		description:
			'New user accounts are assigned an admin or superuser role by default in the registration or seed logic, violating least-privilege.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source', 'migration'],
		pattern: {
			type: 'regex',
			value: '(?:role|roles)\\s*[=:]\\s*["\'](?:admin|superuser|root|administrator)["\'](?![^{]*isDefault\\s*:\\s*false)',
			flags: 'i',
			explanation:
				'Detects default-role assignments that grant administrative access at object creation.',
		},
		remediation:
			'Assign the least-privileged role (e.g., "user" or "viewer") by default. Admin roles must be granted explicitly through an audited approval process.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-029',
		criteria: 'CC6.3',
		category: 'security',
		title: 'Kubernetes ClusterRole with wildcard verbs',
		description:
			'A Kubernetes ClusterRole grants all verbs ("*") on API resources, providing unrestricted cluster-level access to the bound service account or user.',
		severity: 'critical',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'regex',
			value: 'verbs\\s*:\\s*\\[\\s*"\\*"\\s*\\]',
			explanation:
				'Matches Kubernetes RBAC role definitions that grant all verbs on API resources.',
		},
		remediation:
			'Replace wildcard verbs with the minimum required set (e.g., ["get", "list"]). Prefer Role over ClusterRole when cluster-wide access is not needed.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-030',
		criteria: 'CC6.3',
		category: 'security',
		title: 'Overly permissive S3 bucket policy (public access)',
		description:
			'An S3 bucket policy grants s3:* or s3:GetObject to Principal: "*", making bucket contents publicly readable or writable.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac', 'config'],
		pattern: {
			type: 'regex',
			value: '"Principal"\\s*:\\s*"\\*"',
			explanation:
				'Matches S3 (or other) resource policies that grant access to any AWS principal, including unauthenticated users.',
		},
		remediation:
			'Remove public principal grants. Enable S3 Block Public Access at the account and bucket level. Use bucket policies that restrict access to specific IAM principals or VPC endpoints.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-031',
		criteria: 'CC6.3',
		category: 'security',
		title: 'Missing resource-level permission check in multi-tenant app',
		description:
			'Multi-tenant application routes do not verify that the requesting tenant owns the resource being accessed, enabling cross-tenant data leakage.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:tenant_id|tenantId|org_id|orgId|workspace_id)\\s*(?:===|==|=)',
			flags: 'i',
			explanation:
				'Flags route handlers in multi-tenant code that do not filter or compare tenant identifiers before returning data.',
		},
		remediation:
			'Scope all database queries to the authenticated tenant\'s identifier. Enforce tenant isolation at the data-access layer, not just the route layer.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-032',
		criteria: 'CC6.3',
		category: 'security',
		title: 'Hardcoded role list in authorization check',
		description:
			'Role names used in authorization checks are hardcoded string literals scattered throughout the codebase, making it easy to miss a check when adding a new role or route.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:role\\s*===\\s*["\']admin["\']|role\\s*===\\s*["\']superuser["\'])',
			flags: 'i',
			explanation:
				'Detects inline string comparisons for role names, which should be centralised constants.',
		},
		remediation:
			'Define roles as an enum or constant file and import them. Centralise permission checks in a single authorization service or middleware.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-033',
		criteria: 'CC6.3',
		category: 'security',
		title: 'Service account with cluster-admin binding',
		description:
			'A Kubernetes service account is bound to the cluster-admin ClusterRole, granting it unrestricted access to all Kubernetes resources.',
		severity: 'critical',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'regex',
			value: 'roleRef\\s*:\\s*[\\s\\S]*?name\\s*:\\s*cluster-admin',
			flags: 'i',
			explanation:
				'Matches Kubernetes RoleBinding or ClusterRoleBinding that references the built-in cluster-admin role.',
		},
		remediation:
			'Create a custom ClusterRole with the minimum required permissions for the service account. Never bind application service accounts to cluster-admin.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-034',
		criteria: 'CC6.3',
		category: 'security',
		title: 'Terraform resource with no IAM condition',
		description:
			'A Terraform IAM policy document resource does not include any condition blocks, granting permissions without any contextual restrictions such as IP, MFA, or request time.',
		severity: 'medium',
		languages: ['any'],
		targets: ['iac'],
		pattern: {
			type: 'absence',
			value: 'condition\\s*\\{',
			flags: 'i',
			explanation:
				'Flags IAM policy Terraform resources that grant actions without conditions such as MFA or source-IP restrictions.',
		},
		remediation:
			'Add IAM conditions where appropriate: require MFA for console access, restrict source IPs for service accounts, and use aws:RequestedRegion to limit geographic scope.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-035',
		criteria: 'CC6.3',
		category: 'security',
		title: 'Missing scope validation on OAuth access token',
		description:
			'The application does not validate the scopes contained in an OAuth access token before performing actions on behalf of the user, allowing tokens with limited scope to access resources beyond their grant.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:scope|scopes|token\\.scope|hasScope|checkScope|requiredScope)',
			flags: 'i',
			explanation:
				'Flags OAuth-protected handlers that do not inspect the scopes claim on the access token.',
		},
		remediation:
			'Validate the required scope for every protected endpoint. Reject access tokens that lack the necessary scope with HTTP 403.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	// ─── CC6.4 Access Restriction (rules 036–045) ─────────────────────────────

	{
		id: 'cc6-036',
		criteria: 'CC6.4',
		category: 'security',
		title: 'IP allowlist check skipped in middleware chain',
		description:
			'An IP-based allowlist middleware is present but is not applied to a route or is bypassed by route ordering, allowing traffic from disallowed IP ranges.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:ipWhitelist|allowlist|ip_filter|ip_allowlist|trusted_proxy|X-Forwarded-For)',
			flags: 'i',
			explanation:
				'Flags admin or internal-only routes that are not protected by an IP allowlist middleware.',
		},
		remediation:
			'Apply IP allowlist middleware to all admin and internal-only routes. Ensure middleware is declared before route handlers. Use X-Forwarded-For carefully behind a trusted reverse proxy.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-037',
		criteria: 'CC6.4',
		category: 'security',
		title: 'Exposed admin interface without network restriction',
		description:
			'An admin panel or management interface is bound to 0.0.0.0 or listens on a public-facing port without network-level access controls.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source', 'config', 'dockerfile'],
		pattern: {
			type: 'regex',
			value: '(?:listen\\s*\\(?\\s*["\']0\\.0\\.0\\.0["\']|host\\s*[=:]\\s*["\']0\\.0\\.0\\.0["\'])',
			flags: 'i',
			explanation:
				'Detects server bindings to all interfaces (0.0.0.0) which expose the service on public network interfaces.',
		},
		remediation:
			'Bind admin interfaces to localhost (127.0.0.1) or an internal VPC subnet. Use a VPN or bastion host for remote admin access. Apply security groups or firewall rules as an additional layer.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-038',
		criteria: 'CC6.4',
		category: 'security',
		title: 'Debug endpoint accessible in production',
		description:
			'A debug, profiling, or diagnostic endpoint (e.g., /debug/pprof, /actuator, /__debug__) is enabled in production configuration, potentially exposing sensitive runtime data.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: '(?:app\\.use\\s*\\(["\']\\/__debug|router\\.get\\s*\\(["\']\\/debug|app\\.use.*actuator|debug\\.enable\\s*=\\s*true)',
			flags: 'i',
			explanation:
				'Matches route registrations or configuration values that enable debug or diagnostic endpoints.',
		},
		remediation:
			'Disable all debug endpoints in production builds. Gate debug routes behind environment checks (NODE_ENV !== "production") or remove them entirely from production deployments.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-039',
		criteria: 'CC6.4',
		category: 'security',
		title: 'Internal API endpoint exposed without VPC boundary',
		description:
			'An internal service endpoint is configured with a public load balancer or public IP, bypassing network segmentation intended to restrict access to internal callers.',
		severity: 'high',
		languages: ['any'],
		targets: ['iac', 'config'],
		pattern: {
			type: 'regex',
			value: '(?:scheme\\s*=\\s*"internet-facing"|internal\\s*=\\s*false|"internet-facing")',
			flags: 'i',
			explanation:
				'Detects Terraform or CloudFormation ALB/NLB configurations set to internet-facing instead of internal.',
		},
		remediation:
			'Use internal load balancers for service-to-service communication. Apply security groups and NACLs to restrict inbound traffic. Use AWS PrivateLink or VPC peering for cross-VPC access.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-040',
		criteria: 'CC6.4',
		category: 'security',
		title: 'Kubernetes Service of type LoadBalancer for internal workload',
		description:
			'A Kubernetes Service for an internal workload is exposed as type LoadBalancer, provisioning a public cloud load balancer and making it reachable from the internet.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'regex',
			value: 'type\\s*:\\s*LoadBalancer',
			explanation:
				'Matches Kubernetes Service manifests that use the LoadBalancer type, which provisions a public cloud load balancer.',
		},
		remediation:
			'Use ClusterIP or NodePort for internal services. For services that must be public, add the annotation service.beta.kubernetes.io/aws-load-balancer-internal to create an internal LB.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-041',
		criteria: 'CC6.4',
		category: 'security',
		title: 'CORS wildcard origin allowing all domains',
		description:
			'The application sets Access-Control-Allow-Origin: * or programmatically echoes back the request Origin without validation, allowing any web page to make credentialed cross-origin requests.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: '(?:Access-Control-Allow-Origin["\']?\\s*:\\s*["\']\\*["\']|origin\\s*:\\s*["\']\\*["\']|cors\\s*\\(\\s*\\))',
			flags: 'i',
			explanation:
				'Matches CORS configuration that allows all origins, or a cors() call with no options (defaults to *).',
		},
		remediation:
			'Configure CORS with an explicit allowlist of trusted origins. Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-042',
		criteria: 'CC6.4',
		category: 'security',
		title: 'Docker container running as root',
		description:
			'The Dockerfile does not switch to a non-root user, causing the container process to run as UID 0 and enabling container escape escalation.',
		severity: 'high',
		languages: ['any'],
		targets: ['dockerfile'],
		pattern: {
			type: 'absence',
			value: '^USER\\s+(?!root)',
			flags: 'im',
			explanation:
				'Flags Dockerfiles that do not contain a USER directive for a non-root user before the CMD/ENTRYPOINT.',
		},
		remediation:
			'Add a USER directive with a non-root user (e.g., USER 1001) before the ENTRYPOINT or CMD instruction. Create the user in the build stage if it does not exist.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-043',
		criteria: 'CC6.4',
		category: 'security',
		title: 'Kubernetes Pod running as privileged',
		description:
			'A Kubernetes Pod or container is configured with securityContext.privileged: true, giving it near-unrestricted access to the host kernel and devices.',
		severity: 'critical',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'regex',
			value: 'privileged\\s*:\\s*true',
			explanation:
				'Matches Kubernetes Pod or container securityContext settings that enable privileged mode.',
		},
		remediation:
			'Remove privileged: true. Use specific Linux capabilities (capabilities.add) only when strictly required and drop all others. Enable seccompProfile and appArmorProfile.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-044',
		criteria: 'CC6.4',
		category: 'security',
		title: 'Unrestricted EC2 security group inbound rule',
		description:
			'An EC2 security group inbound rule allows all traffic (0.0.0.0/0 on port 0/all), exposing the instance to the entire internet.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac', 'config'],
		pattern: {
			type: 'regex',
			value: '(?:cidr_blocks\\s*=\\s*\\[\\s*"0\\.0\\.0\\.0/0"\\s*\\]|CidrIp\\s*:\\s*0\\.0\\.0\\.0/0)',
			explanation:
				'Matches Terraform or CloudFormation security group inbound rules open to the world.',
		},
		remediation:
			'Restrict inbound rules to known CIDR ranges or specific security group IDs. Use AWS PrivateLink or VPN for internal-only services. Never open port 22 (SSH) or 3389 (RDP) to 0.0.0.0/0.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-045',
		criteria: 'CC6.4',
		category: 'security',
		title: 'Application listening on all interfaces in container',
		description:
			'A containerised application binds its HTTP server to 0.0.0.0, making it reachable on all container network interfaces, including those that may be unintentionally exposed.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source', 'dockerfile'],
		pattern: {
			type: 'regex',
			value: '(?:listen\\s*\\(\\s*\\d+\\s*,\\s*["\']0\\.0\\.0\\.0["\']|HOST\\s*=\\s*["\']0\\.0\\.0\\.0["\'])',
			flags: 'i',
			explanation:
				'Detects explicit 0.0.0.0 binding inside application server code or container environment variables.',
		},
		remediation:
			'Unless explicitly required, bind to 127.0.0.1 inside the container and let the container runtime or load balancer handle external exposure. Document any intentional 0.0.0.0 bindings.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	// ─── CC6.5 Logical Access Removal (rules 046–053) ─────────────────────────

	{
		id: 'cc6-046',
		criteria: 'CC6.5',
		category: 'security',
		title: 'Missing account deactivation hook on user deletion',
		description:
			'The user-deletion code path does not revoke active sessions or tokens before removing the account record, leaving previously issued credentials functional.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:revokeTokens|invalidateSessions|deleteUserTokens|session\\.destroyAll|revoke_user_tokens)',
			flags: 'i',
			explanation:
				'Flags user-delete handlers that do not call a token or session revocation function before removing the user record.',
		},
		remediation:
			'Before deleting a user record, revoke all active sessions and refresh tokens. Consider a deactivation step that prevents login before full deletion.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-047',
		criteria: 'CC6.5',
		category: 'security',
		title: 'No token revocation mechanism (refresh token not invalidated)',
		description:
			'The application issues refresh tokens but does not maintain a token store or denylist, making it impossible to revoke tokens before their expiry.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:tokenDenylist|revokedTokens|token_blacklist|refreshTokenStore|invalidateRefreshToken)',
			flags: 'i',
			explanation:
				'Flags codebases that issue refresh tokens but contain no storage or check for revoked tokens.',
		},
		remediation:
			'Maintain a server-side token store (Redis, database) to track issued refresh tokens. Check for revocation on every token exchange and revoke all tokens on logout or account compromise.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-048',
		criteria: 'CC6.5',
		category: 'security',
		title: 'Missing session cleanup on password change',
		description:
			'When a user changes their password, existing sessions for other devices or browsers are not invalidated, allowing a compromised session to remain active.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:destroyOtherSessions|invalidateOtherSessions|logoutAllDevices|revokeOtherTokens)',
			flags: 'i',
			explanation:
				'Flags password-change handlers that do not invalidate sessions or tokens on other devices.',
		},
		remediation:
			'On password change, invalidate all sessions except the current one. Provide a "log out all other devices" option. Notify the user of the password change by email.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-049',
		criteria: 'CC6.5',
		category: 'security',
		title: 'Stale service account credentials not rotated',
		description:
			'Service account API keys or secrets are hardcoded or stored without a rotation schedule, meaning compromised credentials remain valid indefinitely.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac', 'cicd'],
		pattern: {
			type: 'regex',
			value: '(?:service_account_key|serviceAccountKey|GOOGLE_APPLICATION_CREDENTIALS|AWS_SECRET_ACCESS_KEY)\\s*[=:]\\s*["\'][^"\'\\s]{16,}["\']',
			flags: 'i',
			explanation:
				'Detects long-lived service account credentials stored as literal strings in config or CI/CD files.',
		},
		remediation:
			'Store service account credentials in a secrets manager. Enable automatic rotation with AWS Secrets Manager or HashiCorp Vault. Use IAM roles for EC2/Lambda/GCP workload identity instead of static keys.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-050',
		criteria: 'CC6.5',
		category: 'security',
		title: 'API key not invalidated after rotation in code',
		description:
			'Code references an old API key variable alongside a new one or does not clear the old credential from environment/config, leaving both valid simultaneously.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: '(?:OLD_API_KEY|LEGACY_SECRET|PREVIOUS_TOKEN|old_password|old_secret)',
			flags: 'i',
			explanation:
				'Matches variable names that suggest legacy or pre-rotation credentials are still referenced in code.',
		},
		remediation:
			'Remove all references to old credentials immediately after rotation. Automate rotation through secrets manager APIs and ensure only one active credential version exists at a time.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-051',
		criteria: 'CC6.5',
		category: 'security',
		title: 'Orphaned IAM user without MFA',
		description:
			'An IAM user resource in Terraform does not enforce MFA on console login, leaving the account vulnerable if credentials are compromised.',
		severity: 'high',
		languages: ['any'],
		targets: ['iac'],
		pattern: {
			type: 'absence',
			value: 'aws_iam_user_login_profile|virtual_mfa_device|mfa_configuration',
			flags: 'i',
			explanation:
				'Flags Terraform aws_iam_user resources that are not paired with MFA enforcement.',
		},
		remediation:
			'Attach an IAM policy that denies all actions unless MFA is present (aws:MultiFactorAuthPresent). Prefer IAM roles over long-lived IAM users for programmatic access.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-052',
		criteria: 'CC6.5',
		category: 'security',
		title: 'Disabled user account still has active access tokens',
		description:
			'The account-disabling workflow updates the user\'s enabled flag in the database but does not invalidate tokens in the token store, allowing disabled users to continue API access.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:user\\.enabled|user\\.active|is_active|isEnabled)\\s*=\\s*false(?![\\s\\S]{0,200}(?:revokeTokens|invalidateTokens|deleteTokens))',
			flags: 'i',
			explanation:
				'Detects code that disables a user account without subsequently revoking their tokens.',
		},
		remediation:
			'On account deactivation, immediately revoke all active access and refresh tokens. Verify token validity against account status on every authenticated request.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-053',
		criteria: 'CC6.5',
		category: 'security',
		title: 'Long-lived personal access token without expiry',
		description:
			'Personal access tokens (PATs) are generated without an expiration date, creating permanent credentials that remain valid even after the user\'s intent has changed.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'generateToken\\s*\\([^)]*\\)(?![\\s\\S]{0,300}(?:expiresAt|expires_at|expiresIn|expire))',
			flags: 'i',
			explanation:
				'Detects token generation calls where no expiry is assigned in the nearby code.',
		},
		remediation:
			'Require an expiry date on all PATs (max 1 year). Notify users before expiry and provide an easy rotation workflow. List active tokens in account settings for user review.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	// ─── CC6.6 Logical Access Modification (rules 054–061) ────────────────────

	{
		id: 'cc6-054',
		criteria: 'CC6.6',
		category: 'security',
		title: 'No access review automation',
		description:
			'The codebase lacks any scheduled job or trigger that flags or reports on access permissions that have not been reviewed within the required period.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source', 'cicd'],
		pattern: {
			type: 'absence',
			value: '(?:accessReview|access_review|permissionAudit|role_review|quarterly_review)',
			flags: 'i',
			explanation:
				'Flags codebases with no evidence of periodic access review automation.',
		},
		remediation:
			'Implement a scheduled job (cron) that generates access review reports and sends them to resource owners. Integrate with an IAM governance tool to automate recertification workflows.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc6-055',
		criteria: 'CC6.6',
		category: 'security',
		title: 'Missing audit log for access permission change',
		description:
			'Role assignments, permission grants, or group membership changes are not written to an immutable audit log, preventing investigation of unauthorized privilege changes.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:auditLog|audit_log|accessLog|logPermissionChange|logRoleChange)',
			flags: 'i',
			explanation:
				'Flags permission-modification code paths that do not emit an audit log entry.',
		},
		remediation:
			'Emit an immutable audit log record for every permission change, including: actor, target user, changed permission, timestamp, and justification. Store audit logs in a tamper-evident store.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc6-056',
		criteria: 'CC6.6',
		category: 'security',
		title: 'Unauthorized permission grant by non-admin',
		description:
			'The permission-grant API does not verify that the caller holds a sufficient privilege level, allowing regular users to escalate their own or others\' permissions.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:isAdmin|hasRole.*admin|requireRole|authorize.*admin|can.*managePermissions)',
			flags: 'i',
			explanation:
				'Flags permission-grant route handlers that contain no admin or super-user role assertion.',
		},
		remediation:
			'Gate all permission-granting APIs behind an admin role check. Implement approval workflows for role changes above a certain privilege tier.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-057',
		criteria: 'CC6.6',
		category: 'security',
		title: 'Missing approval workflow for elevated access changes',
		description:
			'Requests for elevated access (e.g., admin, DBA, network-admin roles) are fulfilled immediately without requiring a second approver or change-ticket validation.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:approvalRequired|requiresApproval|ticketId|approver|approval_workflow|jira|servicenow)',
			flags: 'i',
			explanation:
				'Flags elevated-access provisioning code that does not reference an approval or ticketing mechanism.',
		},
		remediation:
			'Implement a request-approval workflow: the requester submits a justification, a manager approves, and access is time-bound. Integrate with ITSM tools for audit trail.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc6-058',
		criteria: 'CC6.6',
		category: 'security',
		title: 'Bulk role assignment without individual review',
		description:
			'A migration or script assigns roles to multiple users in a single bulk operation without per-user justification or review, risking accidental over-provisioning.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source', 'migration'],
		pattern: {
			type: 'regex',
			value: '(?:updateMany|update_all|bulkUpdate|mass_assign)\\s*\\([^)]*(?:role|permission)',
			flags: 'i',
			explanation:
				'Detects bulk-update operations that modify role or permission fields across many records.',
		},
		remediation:
			'Avoid bulk role assignments in migrations. If required, add a dry-run mode, log every record modified, and require a human approval step before execution.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc6-059',
		criteria: 'CC6.6',
		category: 'security',
		title: 'Role change not communicated to user',
		description:
			'When a user\'s role is elevated or downgraded, no notification is sent to the user or their manager, preventing awareness of unexpected access changes.',
		severity: 'low',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:sendEmail|notify|notification|sendNotification|alertUser)',
			flags: 'i',
			explanation:
				'Flags role-change handlers that do not emit a notification to the affected user or an administrator.',
		},
		remediation:
			'Send an email or in-app notification to the user and their manager whenever their role changes. Include the old role, new role, actor, and timestamp.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc6-060',
		criteria: 'CC6.6',
		category: 'security',
		title: 'Temporary elevated access not time-bounded',
		description:
			'Temporary or break-glass elevated access is granted without an automatic expiry, resulting in permanent privilege escalation if cleanup is forgotten.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:expiresAt|expires_at|temporaryAccess|time_bound|ttl|validUntil)',
			flags: 'i',
			explanation:
				'Flags temporary access grant functions that do not set an expiry timestamp on the granted permission.',
		},
		remediation:
			'Assign an expiry timestamp to every temporary permission grant. Implement a background job to revoke expired grants. Send an expiry warning 24 hours before revocation.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc6-061',
		criteria: 'CC6.6',
		category: 'security',
		title: 'Access change performed directly in production database',
		description:
			'Role or permission changes are applied by running raw SQL statements directly against the production database rather than through the application\'s access management API.',
		severity: 'high',
		languages: ['any'],
		targets: ['migration', 'source'],
		pattern: {
			type: 'regex',
			value: 'UPDATE\\s+(?:users|accounts|principals)\\s+SET\\s+(?:role|permission|is_admin)',
			flags: 'i',
			explanation:
				'Matches raw SQL UPDATE statements that modify role or permission columns, bypassing application-layer controls.',
		},
		remediation:
			'All access changes must go through the application\'s access-management API, which enforces authorization checks and audit logging. Restrict direct database write access to automated migration pipelines only.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	// ─── CC6.7 Unauthorized Access Protection (rules 062–076) ─────────────────

	{
		id: 'cc6-062',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Missing brute-force protection on login endpoint',
		description:
			'The authentication endpoint does not implement rate limiting, exponential backoff, or account lockout, allowing unlimited password attempts.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:rateLimit|rate_limit|loginAttempts|failedAttempts|lockout|backoff|throttle)',
			flags: 'i',
			explanation:
				'Flags login route handlers that contain no rate-limiting, lockout, or throttling logic.',
		},
		remediation:
			'Apply rate limiting to the login endpoint (e.g., 5 attempts per 15 minutes per IP). Implement progressive delays or temporary lockout after repeated failures.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-063',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Account lockout not implemented',
		description:
			'Failed login attempts are counted but the account is never locked, allowing indefinite brute-force attempts after the counter threshold is reached.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'failedAttempts\\s*(?:\\+\\+|\\+=\\s*1|=\\s*failedAttempts\\s*\\+\\s*1)(?![\\s\\S]{0,500}(?:locked|isLocked|lockAccount|account_locked))',
			flags: 'i',
			explanation:
				'Detects code that increments a failed-attempt counter but does not follow it with a lockout action.',
		},
		remediation:
			'Lock the account after N consecutive failures (e.g., 10). Use a time-based lock (e.g., 30 minutes) or require email-based unlock. Log all lockout events.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-064',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Timing attack in password comparison',
		description:
			'Passwords or tokens are compared using a standard equality operator (== or ===), which short-circuits on the first differing byte and is vulnerable to timing side-channel attacks.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:token|password|secret|apiKey|hmac)\\s*(?:===|==)\\s*(?:req\\.|expected|stored)',
			flags: 'i',
			explanation:
				'Matches direct string equality comparisons of tokens or secrets, which are susceptible to timing attacks.',
		},
		remediation:
			'Use a constant-time comparison function: crypto.timingSafeEqual() in Node.js, hmac.compare_digest() in Python, MessageDigest.isEqual() in Java.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-065',
		criteria: 'CC6.7',
		category: 'security',
		title: 'User enumeration via distinct error messages',
		description:
			'Login or password-reset endpoints return different error messages for unknown usernames versus wrong passwords, enabling an attacker to enumerate valid accounts.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:User not found|No account with that email|Username does not exist|Invalid username)',
			flags: 'i',
			explanation:
				'Matches specific error messages that reveal whether a username or email exists in the system.',
		},
		remediation:
			'Return a generic error message for both unknown usernames and wrong passwords (e.g., "Invalid credentials"). Add the same artificial delay regardless of which check failed.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-066',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Insecure password reset token (short or predictable)',
		description:
			'Password reset tokens are generated with insufficient entropy (e.g., 6-digit numeric codes or Math.random()), making them feasible to brute-force or predict.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:Math\\.floor\\s*\\(\\s*Math\\.random\\s*\\(\\)\\s*\\*\\s*(?:100|1000|10000|100000|1000000)\\s*\\)|reset_token\\s*=\\s*str\\s*\\(\\s*random\\.randint)',
			flags: 'i',
			explanation:
				'Detects password reset token generation using non-CSPRNG sources or obviously short numeric tokens.',
		},
		remediation:
			'Generate password reset tokens with at least 128 bits of entropy using a CSPRNG (crypto.randomBytes(32)). Expire tokens after 15 minutes. Invalidate them after a single use.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-067',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Password reset token not invalidated after use',
		description:
			'After a successful password reset, the reset token is not removed or marked as used, allowing replay attacks if the token is intercepted.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:deleteResetToken|resetToken\\s*=\\s*null|invalidateToken|token\\.used\\s*=\\s*true|clearResetToken)',
			flags: 'i',
			explanation:
				'Flags password-reset completion handlers that do not delete or invalidate the token after use.',
		},
		remediation:
			'Delete or mark the reset token as used immediately after the password is changed. Also expire tokens server-side after 15 minutes regardless of use.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-068',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Security questions used as authentication factor',
		description:
			'The application relies on knowledge-based authentication (KBA) security questions for identity verification, which are easily guessable from social media or public records.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:securityQuestion|security_question|kbaQuestion|mothersMaidenName|petName|firstSchool)',
			flags: 'i',
			explanation:
				'Matches field names and variable references associated with knowledge-based security questions.',
		},
		remediation:
			'Replace security questions with TOTP-based MFA, WebAuthn/FIDO2, or email/SMS OTP. If KBA cannot be removed immediately, supplement it with a stronger factor.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-069',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Missing CAPTCHA on public-facing authentication forms',
		description:
			'Login, registration, and password-reset forms have no CAPTCHA or proof-of-work mechanism, making them trivially automatable for credential-stuffing attacks.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:captcha|recaptcha|hcaptcha|turnstile|proofOfWork|pow_challenge)',
			flags: 'i',
			explanation:
				'Flags authentication form handlers that contain no reference to CAPTCHA or proof-of-work validation.',
		},
		remediation:
			'Integrate Google reCAPTCHA v3, hCaptcha, or Cloudflare Turnstile on login, registration, and password-reset endpoints. Validate the challenge server-side.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-070',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Credential stuffing protection absent',
		description:
			'The login endpoint does not check submitted credentials against known-breached password datasets (e.g., HIBP Pwned Passwords), allowing accounts protected by previously leaked passwords to be compromised.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:pwnedPassword|hibp|haveibeenpwned|breachedPassword|pwned_passwords)',
			flags: 'i',
			explanation:
				'Flags authentication or registration flows that do not check passwords against breach databases.',
		},
		remediation:
			'Integrate the Have I Been Pwned Passwords API (k-Anonymity model) into the login and registration flow. Prompt users with breached passwords to change them.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-071',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Missing honeypot field to detect automated login bots',
		description:
			'Login and registration forms lack a hidden honeypot field to detect automated form submission tools, reducing the ability to identify bot traffic early.',
		severity: 'low',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:honeypot|hp_field|bot_field|trap_field|hidden_field)',
			flags: 'i',
			explanation:
				'Flags form processing handlers that do not check for a honeypot field to detect bots.',
		},
		remediation:
			'Add a hidden form field that legitimate users never fill in. Reject any submission where this field is populated. Combine with CAPTCHA and rate limiting for layered bot defense.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},

	{
		id: 'cc6-072',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Password reset link sent over HTTP',
		description:
			'Password reset emails contain links that use HTTP instead of HTTPS, exposing the one-time token to network eavesdroppers.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: '["\']http://[^"\']*(?:reset|token|verify)',
			flags: 'i',
			explanation:
				'Detects reset or verification link construction using the http:// scheme.',
		},
		remediation:
			'Always generate reset links with https://. Enforce HSTS on the domain. Validate that APP_URL/BASE_URL is always set to an https:// value.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-073',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Concurrent session limit not enforced',
		description:
			'The application allows unlimited concurrent sessions for a single user, making it impossible to detect or prevent session hijacking by a second party.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:maxSessions|sessionLimit|concurrentSessions|singleSession|max_concurrent)',
			flags: 'i',
			explanation:
				'Flags session-creation logic that does not enforce a maximum concurrent session count per user.',
		},
		remediation:
			'Enforce a maximum number of concurrent sessions per user (e.g., 5). On session creation, evict the oldest session when the limit is exceeded. Notify the user of new sign-ins.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-074',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Authentication response leaks stack trace',
		description:
			'Authentication error responses include a stack trace or detailed internal error messages, providing attackers with system architecture information.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'res\\.(?:json|send|status)\\s*\\([^)]*(?:err\\.stack|error\\.stack|e\\.stackTrace)',
			flags: 'i',
			explanation:
				'Detects error response code that sends a stack trace directly to the client.',
		},
		remediation:
			'Never expose stack traces or internal error details to clients. Log detailed errors server-side and return a generic error message with a correlation ID.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-075',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Missing alert on impossible travel or anomalous login',
		description:
			'The authentication system does not detect or alert on anomalous login patterns such as logins from two geographically distant locations within a short time window.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:impossibleTravel|geoVelocity|loginAnomaly|unusual_login|suspicious_login|anomalous_access)',
			flags: 'i',
			explanation:
				'Flags authentication systems that contain no logic for detecting geographically or behaviourally anomalous login events.',
		},
		remediation:
			'Implement anomaly detection for logins from new locations, devices, or times. Alert the user and optionally require step-up authentication for high-risk events. Integrate with a SIEM for behavioural analytics.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},

	{
		id: 'cc6-076',
		criteria: 'CC6.7',
		category: 'security',
		title: 'Sensitive API response cached by shared proxy',
		description:
			'Authenticated API responses do not include Cache-Control: no-store, allowing shared caches or CDN nodes to serve one user\'s sensitive data to another.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:no-store|no-cache|Cache-Control.*private|cache_control)',
			flags: 'i',
			explanation:
				'Flags authenticated API response handlers that do not set Cache-Control: no-store or equivalent headers.',
		},
		remediation:
			'Set Cache-Control: no-store, Pragma: no-cache on all authenticated API responses. Use Cache-Control: private for user-specific pages that must be cached.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	// ─── CC6.8 Malicious Software Prevention (rules 077–090) ──────────────────

	{
		id: 'cc6-077',
		criteria: 'CC6.8',
		category: 'security',
		title: 'eval() called with user-controlled input',
		description:
			'The eval() function is called with a value derived from user input, enabling arbitrary JavaScript execution in the application\'s context.',
		severity: 'critical',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'eval\\s*\\(\\s*(?:req\\.|res\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Detects eval() calls whose argument originates directly from request data or user-controlled variables.',
		},
		remediation:
			'Never use eval() with untrusted input. Replace dynamic evaluation with a safe JSON parser, a whitelisted function map, or a sandboxed execution environment.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-078',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Python exec() with user-controlled input',
		description:
			'Python\'s exec() or compile() is called with a value derived from user input, enabling arbitrary code execution.',
		severity: 'critical',
		languages: ['python'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:exec|compile)\\s*\\(\\s*(?:request\\.|input\\(|user_|untrusted)',
			flags: 'i',
			explanation:
				'Matches exec() or compile() calls whose first argument includes user-controlled data.',
		},
		remediation:
			'Remove exec()/compile() calls on user input. Use ast.literal_eval() for safe expression evaluation. Implement a domain-specific expression parser if dynamic logic is required.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-079',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Shell injection via child_process with user input',
		description:
			'Node.js child_process functions (exec, execSync, spawn with shell:true) are called with unsanitised user input, enabling OS command injection.',
		severity: 'critical',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:exec|execSync|execFileSync)\\s*\\([^)]*(?:req\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Detects child_process.exec/execSync calls that include user-controlled variables in the command string.',
		},
		remediation:
			'Use child_process.execFile() with a pre-defined executable path and a separate arguments array. Never construct shell commands by concatenating user input. Whitelist and validate all inputs before use.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-080',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Python subprocess shell=True with user input',
		description:
			'Python\'s subprocess module is called with shell=True and a command that incorporates user-supplied data, creating a shell injection vulnerability.',
		severity: 'critical',
		languages: ['python'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'subprocess\\.(?:run|call|Popen|check_output)\\s*\\([^)]*shell\\s*=\\s*True',
			flags: 'i',
			explanation:
				'Matches subprocess calls with shell=True, which invoke a shell and are vulnerable to injection when the command includes user data.',
		},
		remediation:
			'Use shell=False (the default) and pass command arguments as a list. If shell=True is unavoidable, sanitise and validate all inputs rigorously with shlex.quote().',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-081',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Arbitrary file read via path traversal',
		description:
			'File paths passed to fs.readFile, open(), or similar functions are constructed from user input without normalisation, enabling path traversal attacks that read arbitrary files.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:readFile|readFileSync|open\\s*\\(|fopen)\\s*\\([^)]*(?:req\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Detects file-read calls that incorporate user-controlled path components.',
		},
		remediation:
			'Resolve the file path with path.resolve() and verify it starts with the intended base directory. Use a whitelist of allowed file names. Never allow ".." in user-supplied paths.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-082',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Arbitrary file write via path traversal',
		description:
			'File paths used for write operations are constructed from user input without normalisation, enabling attackers to overwrite arbitrary files such as configuration or source files.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:writeFile|writeFileSync|write\\s*\\(|fwrite|open.*["\']w["\'])\\s*\\([^)]*(?:req\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Detects file-write calls that incorporate user-controlled path components.',
		},
		remediation:
			'Normalise and canonicalise the path before writing. Restrict write operations to a specific safe directory. Use a randomised filename instead of user-supplied names.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-083',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Server-Side Request Forgery (SSRF) via user-controlled URL',
		description:
			'The application makes HTTP requests to a URL that is partially or fully controlled by user input without validating the destination, enabling SSRF attacks against internal services.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:fetch|axios\\.get|requests\\.get|http\\.get|urllib)\\s*\\([^)]*(?:req\\.|params\\.|query\\.|body\\.|url|input)',
			flags: 'i',
			explanation:
				'Matches HTTP client calls that use user-controlled variables as the request URL.',
		},
		remediation:
			'Validate URLs against an allowlist of permitted hosts and schemes. Block requests to RFC-1918 address ranges (10.x, 172.16-31.x, 192.168.x) and loopback addresses. Use a dedicated egress proxy.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-084',
		criteria: 'CC6.8',
		category: 'security',
		title: 'npm install without lockfile (dependency confusion risk)',
		description:
			'npm install is run without a lockfile (package-lock.json or yarn.lock), allowing dependency versions to float and enabling dependency confusion or hijacking attacks.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'dockerfile'],
		pattern: {
			type: 'regex',
			value: '\\bnpm\\s+install\\b(?!.*(?:--frozen-lockfile|--ci|ci\\b))',
			flags: 'i',
			explanation:
				'Matches npm install commands that do not use --ci or --frozen-lockfile, indicating lockfile is not enforced.',
		},
		remediation:
			'Use "npm ci" in CI/CD pipelines to install from the lockfile exactly. Commit package-lock.json to version control. Enable npm audit in the pipeline.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-085',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Dependency confusion risk via unscoped internal package',
		description:
			'The package.json references internal package names that are not scoped (e.g., @company/pkg), making them susceptible to dependency confusion attacks if a public package with the same name is published.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['config'],
		pattern: {
			type: 'regex',
			value: '"dependencies"\\s*:\\s*\\{[^}]*"[a-z][a-z0-9-]*"\\s*:\\s*"(?:file:|git\\+|\\^[0-9])',
			flags: 'i',
			explanation:
				'Detects unscoped package names in dependencies that could be shadowed by malicious public packages.',
		},
		remediation:
			'Scope all internal packages with your organisation\'s npm scope (e.g., @acme/pkg). Configure an .npmrc to resolve scoped packages from your private registry first.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-086',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Missing subresource integrity (SRI) on external scripts',
		description:
			'HTML pages load JavaScript or CSS from external CDNs without a Subresource Integrity (SRI) hash, allowing a compromised CDN to serve malicious code.',
		severity: 'high',
		languages: ['any'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '<script[^>]+src=["\']https?://(?!localhost)[^"\']+["\'](?![^>]*integrity=)',
			flags: 'i',
			explanation:
				'Matches <script> tags loading external resources that lack an integrity attribute.',
		},
		remediation:
			'Add integrity and crossorigin attributes to all external script and stylesheet tags. Generate SRI hashes with openssl or use https://www.srihash.org. Prefer self-hosting critical assets.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-087',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Dynamic require() with user-controlled module name',
		description:
			'A Node.js require() call uses a variable derived from user input to load a module, potentially allowing path traversal to load arbitrary modules or executing malicious code.',
		severity: 'critical',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'require\\s*\\(\\s*(?:req\\.|params\\.|query\\.|body\\.|input|user)',
			flags: 'i',
			explanation:
				'Detects require() calls whose argument is user-controlled, enabling module injection.',
		},
		remediation:
			'Never use require() with user-supplied input. Use a static module whitelist object and look up the key by user input. Validate against a strict whitelist before any dynamic import.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-088',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Deserialization of untrusted data',
		description:
			'The application deserialises data from user-controlled sources using unsafe methods (pickle, unserialize, ObjectInputStream), enabling remote code execution via gadget chains.',
		severity: 'critical',
		languages: ['python', 'php', 'java', 'ruby', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:pickle\\.loads|pickle\\.load|unserialize\\s*\\(|ObjectInputStream|Marshal\\.load|BinaryFormatter\\.Deserialize)\\s*\\([^)]*(?:request|input|body|user|untrusted)',
			flags: 'i',
			explanation:
				'Detects unsafe deserialization calls that receive user-controlled data.',
		},
		remediation:
			'Never deserialise untrusted data with pickle, PHP unserialize, Java ObjectInputStream, or Ruby Marshal. Use a safe format (JSON, Protocol Buffers) and validate the schema after parsing.',
		references: [
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
		],
	},

	{
		id: 'cc6-089',
		criteria: 'CC6.8',
		category: 'security',
		title: 'Dockerfile base image without pinned digest',
		description:
			'The Dockerfile FROM instruction references a mutable tag (e.g., :latest or a version tag without SHA digest), allowing the base image to be silently replaced with a malicious version.',
		severity: 'medium',
		languages: ['any'],
		targets: ['dockerfile'],
		pattern: {
			type: 'regex',
			value: '^FROM\\s+(?!.*@sha256:)[^\\n]+(?::latest|:[a-z0-9._-]+)?\\s*$',
			flags: 'im',
			explanation:
				'Matches FROM instructions that use a mutable tag instead of a pinned SHA-256 image digest.',
		},
		remediation:
			'Pin base images to an immutable SHA-256 digest (e.g., FROM node:20-alpine@sha256:abc123...). Use Dependabot or Renovate to automate digest updates with security scanning.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},

	{
		id: 'cc6-090',
		criteria: 'CC6.8',
		category: 'security',
		title: 'CI/CD pipeline installs dependencies without integrity verification',
		description:
			'The CI/CD pipeline script fetches and installs external scripts or tools using curl/wget and pipes directly to a shell without verifying a checksum or signature.',
		severity: 'critical',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'regex',
			value: '(?:curl|wget)\\s+[^|\\n]*\\|\\s*(?:bash|sh|sudo\\s+bash|sudo\\s+sh)',
			flags: 'i',
			explanation:
				'Matches the dangerous "curl | bash" pattern in CI/CD pipeline scripts, which executes remote code without integrity verification.',
		},
		remediation:
			'Download scripts or binaries to a file first, verify their SHA-256 or GPG signature against a known-good value, then execute them. Use a package manager or official GitHub Actions instead of curl-pipe-bash.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},

	{
		id: 'cc6-091',
		criteria: 'CC6.1',
		category: 'security',
		title: 'JWT Signed with Symmetric Secret in Multi-Service Architecture',
		description:
			'JSON Web Tokens are signed using a symmetric algorithm (HS256, HS384, HS512) with a secret that must be shared with every service that validates tokens. Any service holding the shared secret can also forge tokens, violating the principle that only the issuer should be able to mint credentials.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:jwt\\.sign|jose\\.sign|JWT\\.create|encode)\\s*\\([^)]*["\']HS(?:256|384|512)["\']',
			flags: 'i',
			explanation:
				'Matches JWT creation calls that explicitly select an HMAC-based symmetric algorithm (HS256/384/512). In multi-service architectures this means every verifying service also holds a token-minting capability.',
		},
		remediation:
			'Switch to an asymmetric algorithm (RS256 or ES256). The issuing service holds the private key; all verifying services receive only the public key and therefore cannot mint tokens. Manage the key pair in a secrets manager and publish the public key at a well-known JWKS endpoint.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.rfc-editor.org/rfc/rfc7519',
			'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
		],
	},

	{
		id: 'cc6-092',
		criteria: 'CC6.2',
		category: 'security',
		title: 'Password Reset Token Without Expiry',
		description:
			'Password reset token generation code does not configure an expiry, or sets a time-to-live longer than the recommended one-hour window. Long-lived or non-expiring reset tokens give attackers an extended window to abuse them via email compromise, phishing, or log exposure.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value: '(?:resetToken|reset_token|passwordReset|password_reset)(?:[^;\\n]{0,300})(?:expiresIn|expires_in|ttl|maxAge|expiry|expiration)',
			flags: 'i',
			explanation:
				'Detects password-reset token creation blocks that contain no expiry or TTL configuration. A reset token without an expiry remains valid indefinitely once issued.',
		},
		remediation:
			'Set a maximum validity of 60 minutes on all password reset tokens. After use, immediately invalidate the token by deleting it from the data store or marking it consumed. Enforce single-use semantics: reject any reuse of an already-consumed token.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
			'https://csrc.nist.gov/publications/detail/sp/800-63b/final',
		],
	},

	{
		id: 'cc6-093',
		criteria: 'CC6.8',
		category: 'security',
		title: 'GraphQL Introspection Enabled Without Environment Guard',
		description:
			'The GraphQL server has introspection enabled without restricting access by environment or authentication. Introspection exposes the complete API schema — all types, fields, queries, and mutations — to unauthenticated users, dramatically lowering the effort required for an attacker to enumerate attack surface.',
		severity: 'medium',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'introspection\\s*:\\s*true(?![\\s\\S]{0,200}NODE_ENV)',
			flags: 'i',
			explanation:
				'Matches GraphQL server initialization that sets introspection: true without a NODE_ENV or equivalent environment guard nearby, indicating introspection is unconditionally enabled.',
		},
		remediation:
			'Gate introspection on the runtime environment: `introspection: process.env.NODE_ENV !== "production"`. If internal schema exploration is needed, protect the introspection endpoint with authentication. Consider persisted queries or a schema registry as a safer alternative to runtime introspection in production.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-api-security/',
			'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
		],
	},
];
