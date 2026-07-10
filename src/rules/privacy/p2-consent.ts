/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const p2Rules: ISoc2Rule[] = [
	{
		id: 'p2-001',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Missing Explicit Consent Before Data Collection',
		description:
			'Data collection routines are invoked without a prior explicit consent check. Collecting personal data without obtaining affirmative, informed consent violates SOC2 P2.1 and major privacy regulations including GDPR Article 6 and CCPA.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(collectData|gatherPersonalInfo|saveUserData|storePersonalData|recordPersonalInfo|captureUserInfo)\\s*\\([^)]*\\)(?!\\s*\\/\\/.*consent)(?![\\s\\S]{0,200}(checkConsent|verifyConsent|hasConsent|consentGranted|isConsentGiven|consentCheck))',
			flags: 'g',
			explanation:
				'Matches data collection function calls that are not preceded or immediately followed by a consent verification call within a short code window.',
		},
		remediation:
			'Ensure every data collection point is gated by an explicit consent verification call (e.g., `if (!consentService.hasConsent(userId, purpose)) return;`). Store consent records with timestamp, version, and scope before initiating any data collection.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'p2-002',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'No Consent Withdrawal Mechanism',
		description:
			'The codebase lacks a route, endpoint, or function that allows users to withdraw previously granted consent. SOC2 P2.1 requires that individuals be able to revoke consent at any time, and failure to provide a withdrawal path violates GDPR Article 7(3).',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(withdrawConsent|revokeConsent|deleteConsent|removeConsent|optOut|consentWithdraw|unsubscribeConsent)',
			explanation:
				'Checks for the absence of any function or route identifier related to consent withdrawal or revocation across all source files.',
		},
		remediation:
			'Implement a dedicated consent withdrawal endpoint (e.g., `DELETE /api/consent/:purposeId` or `POST /api/consent/withdraw`). This handler must immediately cease processing under the revoked purpose, purge downstream caches, and emit a `consent.withdrawn` audit event.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'p2-003',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Missing Consent Versioning',
		description:
			'Consent records or consent-related models do not carry a version identifier. When the privacy policy or terms of service change, un-versioned consent records cannot be linked to the specific policy version a user agreed to, making it impossible to demonstrate valid consent under SOC2 P2.1.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'schema'],
		pattern: {
			type: 'absence',
			value:
				'(consentVersion|consent_version|policyVersion|policy_version|termsVersion|terms_version|consentRevision|consent_revision)',
			explanation:
				'Checks for the absence of any field, column, or variable name that tracks the version of the policy or consent record.',
		},
		remediation:
			'Add a `consentVersion` (or `consent_version`) field to your consent data model, populated from a centrally managed policy version registry. Include the version in every consent record and re-solicit consent whenever the policy version increments.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p2-004',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'No Consent Audit Trail',
		description:
			'Consent grant, withdrawal, and update events are not written to an immutable audit log. SOC2 P2.1 requires demonstrable evidence of consent decisions; the absence of an audit trail prevents forensic reconstruction of a user\'s consent history.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(auditConsent|logConsentEvent|consentAudit|consent_audit|consentLog|consent_log|recordConsentEvent|emitConsentEvent)',
			explanation:
				'Checks for the absence of audit logging calls specifically associated with consent lifecycle events.',
		},
		remediation:
			'Integrate a consent audit logger that appends an immutable record (userId, purposeId, action, policyVersion, timestamp, ipAddress, userAgent) on every consent state change. Store logs in a tamper-evident store separate from the primary application database.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'p2-005',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Missing Age Verification for Minors',
		description:
			'The registration or onboarding flow does not include an age verification step before collecting personal data. Processing data of children under 13 (COPPA) or under 16 (GDPR) without verified parental consent exposes the organisation to regulatory enforcement and violates SOC2 P2.1.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(verifyAge|ageVerification|age_verification|checkAge|isMinor|isUnderage|underageCheck|ageGate|ageCheck)',
			explanation:
				'Checks for the absence of any age-verification or age-gate function across registration and onboarding source files.',
		},
		remediation:
			'Add an age gate to every registration and data-collection entry point. Collect date of birth, compute age server-side, and redirect users who are minors to a parental-consent flow before any personal data is stored.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'p2-006',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'No Parental Consent Mechanisms',
		description:
			'The application does not implement parental consent workflows required when minors are served. COPPA and GDPR Article 8 mandate verifiable parental consent for users under the applicable age threshold, and its absence constitutes a direct violation of SOC2 P2.1.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(parentalConsent|parental_consent|guardianConsent|guardian_consent|parentConsent|parent_consent|copaConsent|coppaConsent)',
			explanation:
				'Checks for the absence of any parental or guardian consent function, class, or variable across the codebase.',
		},
		remediation:
			'Implement a parental consent flow that (1) collects a parent/guardian email, (2) sends a verifiable consent request, (3) stores the verified parental consent record linked to the minor\'s account, and (4) blocks data processing until parental consent is confirmed.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'p2-007',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Missing Opt-In (Not Pre-Ticked) Checkbox Pattern',
		description:
			'Consent UI components use pre-checked or default-true checkbox values, turning opt-out into the required user action rather than opt-in. GDPR Recital 32 explicitly prohibits pre-ticked boxes as a valid consent mechanism, and SOC2 P2.1 requires affirmative action from the data subject.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'<input[^>]+type\\s*=\\s*["\']checkbox["\'][^>]*(checked(?!\\s*=\\s*["\']?false)|defaultChecked)[^>]*(?:consent|marketing|newsletter|terms|privacy|gdpr|subscribe)[^>]*>',
			flags: 'gi',
			explanation:
				'Matches HTML/JSX checkbox inputs that have a `checked` or `defaultChecked` attribute set to true alongside consent-related naming, indicating a pre-ticked consent box.',
		},
		remediation:
			'Remove the `checked` or `defaultChecked` attribute from all consent-related checkboxes so they render unchecked by default. Users must affirmatively tick the box to grant consent. Validate this server-side: reject form submissions where consent fields are absent.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p2-008',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'No Separate Consent Per Purpose',
		description:
			'The consent model stores a single boolean flag for all data-processing purposes rather than granular per-purpose records. Bundled consent violates GDPR Article 7 and SOC2 P2.1 because users cannot selectively grant or revoke consent for individual processing purposes.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'schema'],
		pattern: {
			type: 'regex',
			value:
				'(consentGiven|consent_given|userConsented|user_consented|hasConsented|has_consented)\\s*[=:]\\s*(true|false|boolean|Bool|bool)(?![\\s\\S]{0,500}(purpose|Purpose|purposeId|purpose_id))',
			flags: 'g',
			explanation:
				'Matches single-flag consent field definitions that lack an associated purpose discriminator, indicating bundled rather than per-purpose consent storage.',
		},
		remediation:
			'Replace the single consent boolean with a `ConsentRecord[]` structure keyed by `purposeId` (e.g., `analytics`, `marketing`, `functional`). Each record must include purposeId, granted, grantedAt, version, and withdrawnAt fields.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'p2-009',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Missing Consent Renewal Workflow',
		description:
			'The codebase does not implement logic to detect stale consent records and prompt users to re-confirm. Long-lived consent without renewal can become invalid as processing activities evolve, conflicting with SOC2 P2.1 requirements for current and accurate consent.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(renewConsent|renew_consent|refreshConsent|refresh_consent|consentRenewal|consent_renewal|reconfirmConsent|re_confirm_consent|requestConsentRenewal)',
			explanation:
				'Checks for the absence of any consent renewal or reconfirmation routine that would prompt users to re-grant consent after a defined period.',
		},
		remediation:
			'Implement a scheduled job (e.g., cron) that identifies consent records older than your defined renewal interval (commonly 12–24 months). Trigger an in-app prompt and/or email requesting the user to review and re-confirm their consent preferences.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'p2-010',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'No Consent Portability',
		description:
			'There is no mechanism to export a user\'s consent records in a machine-readable format. SOC2 P2.1 and GDPR Article 20 require that individuals be able to receive and transfer their personal data, which includes their consent history and preferences.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(exportConsent|export_consent|consentExport|consent_export|downloadConsent|download_consent|consentPortability|consent_portability)',
			explanation:
				'Checks for the absence of any consent data export or portability function that would allow users to download their consent records.',
		},
		remediation:
			'Add a `GET /api/consent/export` endpoint that returns the authenticated user\'s full consent history as a structured JSON or CSV document, including all purposes, versions, timestamps, and withdrawal events.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p2-011',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Missing Double Opt-In for Marketing',
		description:
			'Marketing or newsletter subscription flows do not implement a double opt-in confirmation step. Single opt-in for marketing communications is insufficient under CAN-SPAM, CASL, and GDPR guidelines; SOC2 P2.1 requires that consent be demonstrably obtained.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(subscribeToMarketing|subscribeNewsletter|addToMailingList|marketingOptIn|newsletterSignup)\\s*\\([^)]*\\)(?![\\s\\S]{0,600}(doubleOptIn|double_opt_in|confirmEmail|confirmSubscription|verifySubscription|sendConfirmationEmail))',
			flags: 'g',
			explanation:
				'Matches marketing subscription calls that are not followed by a double opt-in confirmation step such as sending a verification email.',
		},
		remediation:
			'After collecting marketing consent, send a confirmation email with a unique tokenised link. Only activate the subscription and store the consent record after the user clicks the confirmation link. Record the confirmation timestamp and IP address.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'p2-012',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'No Consent Expiration Handling',
		description:
			'Consent records are persisted without an expiry timestamp or TTL, and no logic exists to invalidate or flag expired consent. Processing personal data under an expired consent record violates SOC2 P2.1 and may constitute unlawful processing under GDPR.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'schema'],
		pattern: {
			type: 'absence',
			value:
				'(consentExpiry|consent_expiry|consentExpiresAt|consent_expires_at|consentTtl|consent_ttl|consentExpiration|isConsentExpired|consent_expired)',
			explanation:
				'Checks for the absence of consent expiration fields or expiry-check functions across the codebase and schema definitions.',
		},
		remediation:
			'Add a `consentExpiresAt` timestamp field to every consent record. Implement a middleware or decorator that checks whether the relevant consent record has expired before each data-processing operation, and re-solicits consent if it has.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'p2-013',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Missing Consent Scope Documentation',
		description:
			'Consent records do not include a structured description of the data scope (fields, categories, recipients) covered by the consent. Without documented scope, it is impossible to validate that processing stays within the boundaries the user consented to, breaching SOC2 P2.1.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'schema'],
		pattern: {
			type: 'absence',
			value:
				'(consentScope|consent_scope|consentCategories|consent_categories|dataCategories|data_categories|consentDataFields|consent_data_fields)',
			explanation:
				'Checks for the absence of any structured consent scope or data-category field that describes what data the consent covers.',
		},
		remediation:
			'Extend the consent record model with a `scope` object that enumerates the data categories (e.g., `["email","location","behavioural"]`), the processing purposes, and the third-party recipients. Present this scope to the user in plain language at the point of consent.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p2-014',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Consent UI Dark Pattern Detection (Forced Consent)',
		description:
			'UI code contains patterns characteristic of forced-consent dark patterns: making consent refusal a dead-end, using deceptive button labelling, or hiding the decline option. Forced consent is not freely given and is therefore invalid under GDPR and SOC2 P2.1.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(style\\s*=\\s*["\'][^"\']*(?:display\\s*:\\s*none|visibility\\s*:\\s*hidden|opacity\\s*:\\s*0)[^"\']*["\']|className\\s*=\\s*["\'][^"\']*(?:hidden|invisible|sr-only|visually-hidden)[^"\']*["\'])(?=[\\s\\S]{0,300}(?:decline|reject|refuse|deny|disagree|optout|opt-out))',
			flags: 'gi',
			explanation:
				'Matches inline or class-based CSS that hides or makes invisible elements whose nearby text labels relate to declining or rejecting consent, indicating the decline path is being suppressed.',
		},
		remediation:
			'Ensure that accept and decline/reject options are equally visible, accessible, and easy to interact with. Do not use size, colour, or visibility styling to de-emphasise the decline option. Conduct a UX review against the ICO\'s consent dark patterns guidance.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'p2-015',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Missing Legitimate Interest Assessment',
		description:
			'Data processing activities rely on legitimate interest as a legal basis without any code-level record of a Legitimate Interest Assessment (LIA). SOC2 P2.1 requires that the chosen legal basis be documented; undocumented legitimate interest claims cannot be substantiated during an audit.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value:
				'(legalBasis|legal_basis|lawfulBasis|lawful_basis)\\s*[=:,]\\s*["\']?(legitimateInterest|legitimate_interest|LEGITIMATE_INTEREST)["\']?(?![\\s\\S]{0,800}(liaRecord|lia_record|legitimateInterestAssessment|legitimate_interest_assessment|liaCompleted|lia_id))',
			flags: 'gi',
			explanation:
				'Matches processing configuration entries that declare legitimate interest as the legal basis without a corresponding LIA record reference.',
		},
		remediation:
			'For each processing activity using legitimate interest, document and store an LIA that covers the purpose test, necessity test, and balancing test. Attach an `liaRecordId` reference to the processing activity configuration and make the LIA document available for audit.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p2-016',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'No Consent Management Platform Integration',
		description:
			'The application manages consent state in a bespoke, ad-hoc manner without integrating a Consent Management Platform (CMP). Ad-hoc implementations frequently lack the auditability, cross-channel synchronisation, and regulatory update mechanisms that a CMP provides, increasing SOC2 P2.1 compliance risk.',
		severity: 'low',
		languages: ['typescript', 'javascript'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(OneTrust|Cookiebot|TrustArc|Didomi|Usercentrics|CookiePro|Quantcast|ConsentManager|iubenda|consentmanager\\.net|cmp\\.js|cmpApi|__cmp|__tcfapi|window\\.__tcfapi)',
			explanation:
				'Checks for the absence of any known CMP SDK reference, TCF API call, or CMP vendor identifier across frontend source and configuration files.',
		},
		remediation:
			'Integrate an IAB TCF 2.2 compliant CMP (e.g., OneTrust, Didomi, or Cookiebot). Ensure the CMP is loaded before any analytics, advertising, or tracking scripts and that its consent signals are respected by all downstream data processors.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'p2-017',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'Missing Consent for Sensitive Data Categories',
		description:
			'Code that processes special categories of personal data (health, biometric, racial/ethnic origin, political opinions, religious beliefs, sexual orientation) does not gate processing on an explicit, separate consent obtained for that sensitive category. GDPR Article 9 and SOC2 P2.1 impose stricter consent requirements for sensitive data.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(healthData|health_data|biometricData|biometric_data|racialOrigin|racial_origin|politicalOpinion|political_opinion|religiousBelief|religious_belief|sexualOrientation|sexual_orientation|geneticData|genetic_data|mentalHealth|mental_health|medicalRecord|medical_record)\\s*[=({](?![\\s\\S]{0,400}(sensitiveConsent|sensitive_consent|specialCategoryConsent|special_category_consent|explicitConsent|explicit_consent))',
			flags: 'g',
			explanation:
				'Matches assignments or usages of sensitive personal data fields that are not gated by an explicit/special-category consent check within the surrounding code block.',
		},
		remediation:
			'For each sensitive data category processed, implement a separate explicit consent prompt that names the specific category, the purpose, and the legal basis under Article 9(2). Store a `sensitiveConsentRecord` linked to the user and the data category before any processing occurs.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'p2-018',
		criteria: 'P2.1',
		category: 'privacy',
		title: 'No Cross-Device Consent Synchronization',
		description:
			'Consent records are stored locally (e.g., in localStorage or cookies) without synchronisation to a server-side identity-linked consent store. This means that consent granted on one device is not honoured on other devices, and withdrawal on one device does not propagate, violating SOC2 P2.1\'s requirement for consistent consent application.',
		severity: 'medium',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: p2-018-cross-device-consent-sync
    patterns:
      - pattern: |
          localStorage.setItem($KEY, $VALUE)
      - metavariable-regex:
          metavariable: $KEY
          regex: '.*(consent|Consent|CONSENT).*'
      - pattern-not: |
          syncConsentToServer(...)
      - pattern-not: |
          consentApi.sync(...)
      - pattern-not: |
          pushConsentRecord(...)
    message: >
      Consent is being persisted only to localStorage without server-side
      synchronisation. A user who grants or revokes consent on this device
      will not have that preference honoured on other devices.
    languages: [javascript, typescript]
    severity: WARNING`,
			explanation:
				'Detects localStorage writes to consent keys that are not accompanied by a server-side synchronisation call, indicating consent will not propagate across devices.',
		},
		remediation:
			'After writing consent to localStorage, immediately call a server-side API (e.g., `PATCH /api/consent`) to persist the preference against the authenticated user\'s identity. On session start, fetch the server-side consent record and overwrite any stale local state to ensure consistency across all devices and browsers.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
];
