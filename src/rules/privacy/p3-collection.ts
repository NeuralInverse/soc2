/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const p3Rules: ISoc2Rule[] = [
	{
		id: 'p3-001',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'Excessive Personal Data Collection (Data Minimization Violation)',
		description:
			'Code collects broad or unbounded sets of personal data fields without restricting collection to what is strictly necessary for the declared purpose. Patterns such as collecting all request body fields, using wildcard selectors on form data, or copying entire user objects into storage indicate potential data minimization failures under SOC 2 P3.1 and GDPR Article 5(1)(c).',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:collect(?:All|Everything|Full(?:Profile|Data|Record))|req\\.body(?!\\s*\\.\\s*\\w+\\b)|Object\\.assign\\s*\\(\\s*\\{\\s*\\}\\s*,\\s*req\\.body\\s*\\)|spread\\s*req\\.body|\\.\\.\\.(req|request)\\.body|insert(?:Many|One)?\\s*\\(\\s*req\\.body\\s*\\)|save\\s*\\(\\s*req\\.body\\s*\\))',
			flags: 'gi',
			explanation:
				'Detects patterns that copy or persist the entire request body or unbounded user-supplied data directly into storage, indicating a failure to enforce data minimization at the collection point.',
		},
		remediation:
			'Enumerate only the specific fields required for the stated purpose and explicitly pick those fields from incoming data. Use an allowlist-based schema (e.g., Joi, Zod, Pydantic) to strip unexpected fields before any persistence or downstream processing. Document the business justification for each collected field.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'p3-002',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'Missing Purpose Limitation Enforcement',
		description:
			'Personal data is collected or passed to functions without associating a declared, machine-readable purpose. When collection calls lack a purpose annotation, comment, or metadata argument, there is no mechanism to prevent secondary use incompatible with the original collection purpose. This violates SOC 2 P3.1 purpose-limitation requirements.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(?:purpose|collectionPurpose|dataPurpose|processingBasis|legalBasis|retentionPurpose)\\s*[=:]',
			flags: 'i',
			explanation:
				'Flags files that perform personal data collection (store/save/insert/collect patterns) but lack any purpose or legal-basis declaration in the same module, indicating no enforcement of purpose limitation.',
		},
		remediation:
			'Introduce a purpose-limitation framework: each data collection call must supply a structured purpose token (e.g., `{ purpose: "account-creation" }`) that is logged and enforced. Reject or alert on downstream uses whose declared purpose does not match the collection purpose. Maintain a data-purpose registry linked to your privacy policy.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'p3-003',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'No Data Collection Inventory',
		description:
			'The codebase contains data collection logic but no corresponding inventory, registry, or manifest that catalogs what personal data is collected, from whom, for what purpose, and under which legal basis. Without a collection inventory, the organization cannot demonstrate compliance with SOC 2 P3.1 or respond accurately to data subject access requests.',
		severity: 'medium',
		languages: ['any'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(?:dataInventory|collectionInventory|personalDataMap|dataMap|privacyInventory|data[-_]inventory|collection[-_]registry)',
			flags: 'i',
			explanation:
				'Checks for the absence of a data-inventory or personal-data-map reference anywhere in the source or configuration, indicating that no formal collection inventory has been integrated into the codebase.',
		},
		remediation:
			'Create and maintain a machine-readable data collection inventory (e.g., a JSON/YAML manifest or a dedicated registry module) that lists each data element, its source, declared purpose, legal basis, retention period, and responsible team. Reference this inventory from collection code and include it in automated compliance checks.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p3-004',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'Collecting Sensitive Categories Without Extra Safeguards',
		description:
			'Code collects special-category personal data — including health, biometric, genetic, racial or ethnic origin, religious beliefs, sexual orientation, financial account details, or government identifiers — without applying additional access controls, encryption, or consent verification. These categories require heightened protection under SOC 2 P3.1, GDPR Article 9, and HIPAA.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'schema'],
		pattern: {
			type: 'regex',
			value:
				'(?:health(?:Data|Record|Info|Status)|medicalRecord|diagnosis|biometric|fingerprint(?:Data|Hash|Template)|faceId|voicePrint|geneticData|ethnicity|raceData|religion(?:Data|Field)|sexualOrientation|ssn|socialSecurity(?:Number)?|passport(?:Number)?|driversLicense|bankAccount(?:Number)?|creditCard(?:Number)?|routingNumber)',
			flags: 'gi',
			explanation:
				'Detects field names, variable names, and string literals associated with sensitive personal data categories that require elevated safeguards beyond standard personal data.',
		},
		remediation:
			'For each sensitive category: (1) obtain explicit, informed consent before collection; (2) encrypt the data at rest with a dedicated key; (3) apply role-based access controls restricting access to least-privilege personnel; (4) log all access events; (5) document the specific legal basis (e.g., GDPR Art. 9(2)(a)) in your data inventory; and (6) run a Data Protection Impact Assessment (DPIA).',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p3-005',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'Missing Collection Timestamp Recording',
		description:
			'Personal data is collected and stored without recording a timestamp that captures the exact date and time of collection. Absence of collection timestamps prevents accurate data retention enforcement, audit trail reconstruction, and proof of when consent was obtained relative to data collection, all of which are required by SOC 2 P3.1.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'schema', 'migration'],
		pattern: {
			type: 'absence',
			value:
				'(?:collectedAt|collection_timestamp|collected_at|collectionDate|collection_date|dataCollectedAt|capturedAt|captured_at)',
			flags: 'i',
			explanation:
				'Checks that data models and collection code include a collection timestamp field. Absence of these fields in schema definitions or insert/create operations indicates timestamps are not recorded.',
		},
		remediation:
			'Add a `collectedAt` (or `collected_at`) timestamp column/field to every personal data entity. Set the value automatically to the server-side UTC timestamp at the moment of collection — never trust client-supplied timestamps. Index this field for efficient retention policy enforcement and audit queries.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'p3-006',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'No Data Source Tracking',
		description:
			'The system collects personal data from multiple channels (web forms, APIs, third-party imports, SDKs) but does not record the origin or source of each data point. Without source tracking, the organization cannot verify that data was lawfully obtained, cannot respond accurately to data subject queries about data provenance, and cannot fulfill SOC 2 P3.1 collection accountability requirements.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
		targets: ['source', 'schema'],
		pattern: {
			type: 'absence',
			value:
				'(?:dataSource|data_source|collectionSource|collection_source|sourceChannel|source_channel|dataOrigin|data_origin|collectedFrom|collected_from)',
			flags: 'i',
			explanation:
				'Detects the absence of data-source or provenance tracking fields in schemas and collection code, indicating no systematic recording of where personal data originated.',
		},
		remediation:
			'Add a structured `dataSource` field to all personal data records, populated with a canonical source identifier (e.g., `"web-registration-form"`, `"partner-api-acme"`, `"mobile-sdk-v3"`). Store the source alongside the data at collection time. Include source metadata in audit logs and expose it via data subject access request (DSAR) responses.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p3-007',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'Missing Collection Point Documentation',
		description:
			'Data collection endpoints, form handlers, or SDK initialization calls lack inline documentation or annotations that identify the data subject category, fields collected, legal basis, and link to the privacy notice. Without this documentation, developers cannot assess the privacy impact of changes to collection logic, and auditors cannot trace collection practices back to disclosed privacy policies.',
		severity: 'low',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:@(?:PostMapping|GetMapping|RequestMapping|app\\.(?:post|get|put|patch)|router\\.(?:post|get|put|patch))|(?:def\\s+(?:collect|store|save|ingest|capture|record)_(?:user|personal|profile|customer)))',
			flags: 'gi',
			explanation:
				'Identifies collection endpoint decorators and handler function definitions that are likely collection points, where privacy documentation annotations (JSDoc @privacy, Python docstrings, or structured comments) should be present.',
		},
		remediation:
			'Annotate every data collection endpoint and handler with structured privacy metadata using JSDoc `@privacy`, Python docstrings with a `Privacy:` section, or a custom `@CollectionPoint` annotation. Include: data subject category, list of collected fields, legal basis, link to privacy notice section, and data retention period. Enforce this via a linting rule in CI.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p3-008',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'Undisclosed Data Collection (Covert Tracking)',
		description:
			'Code implements tracking, telemetry, or analytics data collection without a corresponding user notification, consent check, or reference to a disclosed privacy notice. Covert collection of behavioral, location, device, or usage data violates SOC 2 P3.1 notice and collection requirements and may constitute an unfair or deceptive practice under FTC regulations.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: p3-008-covert-tracking
    patterns:
      - pattern-either:
          - pattern: $TRACKER.track($DATA)
          - pattern: $TRACKER.identify($DATA)
          - pattern: analytics.track(...)
          - pattern: telemetry.record(...)
          - pattern: $OBJ.sendBeacon(...)
          - pattern: navigator.sendBeacon(...)
      - pattern-not-inside: |
          if ($CONSENT) { ... }
      - pattern-not-inside: |
          if (hasConsent(...)) { ... }
    message: Tracking call found outside a consent guard
    languages: [javascript, typescript]
    severity: ERROR`,
			explanation:
				'Detects analytics, telemetry, and tracking SDK calls that are not wrapped in a consent verification guard, indicating the collection may occur without user knowledge or agreement.',
		},
		remediation:
			'Wrap all tracking and telemetry calls in an explicit consent gate (e.g., `if (consentManager.hasConsent("analytics")) { ... }`). Provide users with a clear notice at collection time that identifies what is tracked and why. Log consent status alongside each tracking event. Implement a consent withdrawal mechanism that immediately stops collection.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},
	{
		id: 'p3-009',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'Missing Cookie Classification',
		description:
			'Cookies are set in code without a classification attribute or accompanying comment that categorizes them as strictly necessary, functional, analytical, or marketing. Unclassified cookies cannot be governed by a cookie consent mechanism and prevent the organization from demonstrating that it collects only the cookie data users have consented to, violating SOC 2 P3.1 and ePrivacy Directive requirements.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:res\\.cookie\\s*\\(|document\\.cookie\\s*=|set_cookie\\s*\\(|setCookie\\s*\\(|response\\.set_cookie\\s*\\(|cookies\\.set\\s*\\()(?:(?!(?:category|classification|cookieType|type\\s*:|necessary|functional|analytics|marketing|httpOnly\\s*:\\s*true|secure\\s*:\\s*true)).)*[\\n;,)]',
			flags: 'gis',
			explanation:
				'Detects cookie-setting calls that lack a category or classification attribute, indicating cookies are being created without a privacy governance classification that would enable proper consent management.',
		},
		remediation:
			'Classify every cookie with a `category` property from a defined taxonomy (`necessary` | `functional` | `analytics` | `marketing`). Integrate with a Consent Management Platform (CMP) that reads this classification and only sets non-necessary cookies after affirmative consent. Document each cookie in a cookie notice that is kept current.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'p3-010',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'No Browser Fingerprinting Detection or Disclosure',
		description:
			'The codebase accesses multiple browser or device properties that, when combined, can be used to fingerprint users without cookies. Collection of fingerprinting signals such as canvas hash, audio context, WebGL renderer, installed fonts, screen resolution, and time zone without disclosure and consent constitutes covert tracking in violation of SOC 2 P3.1 and ePrivacy regulations.',
		severity: 'high',
		languages: ['typescript', 'javascript'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:canvas\\.toDataURL|getImageData\\s*\\(|AudioContext|webkitAudioContext|OfflineAudioContext|gl\\.getParameter|UNMASKED_VENDOR_WEBGL|UNMASKED_RENDERER_WEBGL|navigator\\.plugins|navigator\\.mimeTypes|screen\\.colorDepth|screen\\.pixelDepth|Intl\\.DateTimeFormat\\(\\)\\.resolvedOptions|navigator\\.hardwareConcurrency|navigator\\.deviceMemory)',
			flags: 'gi',
			explanation:
				'Detects JavaScript APIs commonly used in browser fingerprinting: canvas fingerprinting, audio context fingerprinting, WebGL fingerprinting, plugin enumeration, and device characteristic collection.',
		},
		remediation:
			'If fingerprinting is technically necessary, disclose this practice explicitly in your privacy notice and cookie/tracking policy. Obtain explicit opt-in consent before executing fingerprinting code. Provide an opt-out mechanism. Consider whether a less privacy-invasive alternative (e.g., first-party cookies with proper consent) can achieve the same goal. Document the purpose, data minimization measures, and retention period for fingerprint data.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
		],
	},
	{
		id: 'p3-011',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'Missing Pixel Tracking Disclosure',
		description:
			'The application embeds tracking pixels, web beacons, or single-pixel image requests to third-party analytics or advertising platforms without notifying users in the privacy notice or requiring consent. Pixel-based tracking enables third parties to collect IP addresses, browser identifiers, and behavioral data, which must be disclosed under SOC 2 P3.1 and applicable privacy laws.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'php', 'ruby', 'python'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value:
				'(?:new\\s+Image\\s*\\(\\s*1\\s*,\\s*1\\s*\\)|<img[^>]+(?:width=["\']?1["\']?|height=["\']?1["\']?)[^>]+(?:tracking|beacon|pixel|analytics|ads?|tag)[^>]*>|src\\s*=\\s*["\']https?://(?:pixel|beacon|track|analytics|ads?|tag|collect)\\.\\S+["\']|fetch\\s*\\(\\s*["\']https?://(?:pixel|beacon|track|collect))',
			flags: 'gi',
			explanation:
				'Detects 1x1 Image objects, inline pixel image tags targeting tracking domains, and fetch calls to known tracking/beacon URL patterns used for server-side or client-side pixel firing.',
		},
		remediation:
			'List all third-party pixel integrations in your privacy notice, identifying the vendor, purpose, data collected, and any data sharing arrangements. Gate pixel firing on user consent — use your CMP to conditionally load or fire pixels only when the appropriate consent category (e.g., `marketing` or `analytics`) has been granted. Remove pixels for vendors you no longer have a data processing agreement (DPA) with.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'p3-012',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'No Data Broker Relationship Disclosure',
		description:
			'The codebase transmits personal data to third-party data brokers, enrichment services, or audience platforms without a corresponding disclosure in the privacy notice or a reference to a Data Processing Agreement (DPA). Undisclosed data-broker relationships violate SOC 2 P3.1 third-party disclosure requirements and may breach CCPA/CPRA data sale restrictions.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value:
				'(?:clearbit|fullcontact|pipl\\.com|datanyze|lusha|zoominfo|leadspace|demandbase|bombora|6sense|lattice\\.io|enrichment(?:Api|Service|Client)|dataEnrichment|audienceSegment|lookalike(?:Audience|Segment)|thirdPartyEnrich|brokerSync)',
			flags: 'gi',
			explanation:
				'Detects references to known data broker and enrichment service SDKs, API domains, and common data-brokerage integration patterns that indicate personal data is being shared with external data commerce entities.',
		},
		remediation:
			'For each data broker or enrichment vendor: (1) execute a signed DPA; (2) disclose the relationship, data categories shared, and purpose in your privacy notice; (3) implement a user opt-out signal that suppresses broker calls when detected; (4) under CCPA/CPRA, treat broker sharing as a "sale" unless an exemption applies and honor "Do Not Sell or Share" requests; (5) periodically review whether each broker relationship is still necessary and proportionate.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'p3-013',
		criteria: 'P3.1',
		category: 'privacy',
		title: 'Missing Inferred Data Disclosure',
		description:
			'The system generates or stores inferred or derived personal data — such as predicted age, income bracket, risk scores, sentiment classifications, or behavioral segments computed from observed data — without disclosing this inference activity in the privacy notice. Inferred data constitutes personal data under GDPR Recital 26 and CCPA, and its creation must be disclosed and governed under SOC 2 P3.1.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
		targets: ['source', 'schema'],
		pattern: {
			type: 'regex',
			value:
				'(?:inferredAge|predictedAge|estimatedIncome|incomeSegment|riskScore|creditScore|churnScore|propensityScore|sentimentScore|behavioralSegment|audienceSegment|inferredGender|predictedGender|likelyParent|lifestageModel|lookalike(?:Score|Segment)|mlScore|modelScore|derivedAttribute|computed(?:Profile|Segment|Score)|inferred(?:Data|Profile|Attribute|Category))',
			flags: 'gi',
			explanation:
				'Detects field names and variable names associated with inferred, predicted, or ML-derived personal attributes stored alongside or linked to identified individuals, indicating undisclosed inference activity.',
		},
		remediation:
			'Disclose all categories of inferred data in your privacy notice, explaining what is inferred, from what source data, using what methods, and for what purpose. Provide data subjects the right to access inferred data about themselves and to contest inaccurate inferences. Apply the same data minimization and retention controls to inferred data as to directly collected data. Document the legal basis for inference-based profiling, and conduct a DPIA if the profiling produces significant effects on individuals.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},
];
