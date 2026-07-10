/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const p4Rules: ISoc2Rule[] = [
  {
    id: 'p4-001',
    criteria: 'P4.1',
    category: 'privacy',
    title: 'Secondary Use of Personal Data Without Consent',
    description:
      'Personal data is being used for purposes beyond those originally disclosed to the data subject. Secondary use without explicit consent or a compatible legal basis violates privacy principles and regulatory requirements such as GDPR Article 5(1)(b) and CCPA.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:analytics|marketing|advertising|profil(?:e|ing)|recommend(?:ation)?|train(?:ing)?(?:Data|Model)|ml(?:Pipeline|Dataset))\\s*(?:[=:(]|\\bwith\\b)[^;\\n]*(?:user|customer|personal|pii|email|phone|address|dob|birthdate)',
      flags: 'gi',
      explanation:
        'Detects assignments or calls that pass personal data identifiers into analytics, marketing, advertising, profiling, recommendation, or ML training contexts, indicating potential secondary use.',
    },
    remediation:
      'Implement purpose binding at the data-access layer. Before using personal data for a secondary purpose, verify that the data subject has provided explicit consent or that a compatible legal basis exists. Introduce a `DataUseContext` enum and enforce it via middleware or a policy-enforcement point. Log every secondary use with the legal basis applied.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p4-002',
    criteria: 'P4.1',
    category: 'privacy',
    title: 'Missing Purpose Binding Enforcement',
    description:
      'Data access functions lack purpose-binding checks, allowing data to be queried and processed without verifying that the requesting operation is within the original, disclosed purpose. P4.1 requires that personal information is used only for the purposes disclosed at the time of collection.',
    severity: 'high',
    languages: ['typescript', 'javascript'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value: 'purposeBinding|checkPurpose|verifyPurpose|allowedPurpose|DataPurpose',
      flags: 'g',
      explanation:
        'Detects source files that perform database queries or data processing but contain no reference to purpose-binding utilities, suggesting the purpose is never validated before data access.',
    },
    remediation:
      'Create a `PurposeBindingService` that is called before any personal data query. Each data-access method should accept a `DataPurpose` parameter and the service should assert that the requested purpose matches the stored consent record. Annotate data-access functions with a `@RequiresPurpose()` decorator and add a lint rule to enforce its presence.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p4-003',
    criteria: 'P4.2',
    category: 'privacy',
    title: 'No Retention Schedule Configuration',
    description:
      'The application or infrastructure configuration contains no retention schedule definitions. P4.2 requires that personal information is retained only as long as necessary to fulfill the stated purposes or as required by law.',
    severity: 'high',
    languages: ['any'],
    targets: ['config'],
    pattern: {
      type: 'absence',
      value:
        'retentionPeriod|retention_period|retentionDays|retention_days|retentionSchedule|retention_schedule|dataRetention|data_retention',
      flags: 'i',
      explanation:
        'Detects configuration files (YAML, JSON, TOML, .env) that lack any retention period or schedule key, indicating that no structured retention policy has been configured.',
    },
    remediation:
      'Define a `retention` section in your application configuration file. Specify per-data-class retention periods (e.g., `pii: 365d`, `logs: 90d`, `audit: 7y`). Reference this configuration from automated deletion jobs and surface it in your privacy notice. Store the configuration in version control and require a change-control review for modifications.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p4-004',
    criteria: 'P4.2',
    category: 'privacy',
    title: 'Missing Data Lifecycle Management',
    description:
      'No data lifecycle management implementation is present. Without explicit lifecycle states (active, archived, pending deletion, deleted) and transition logic, data may persist indefinitely without oversight, violating P4.2 retention obligations.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'DataLifecycle|data_lifecycle|LifecycleState|lifecycle_state|dataPhase|data_phase|archiveData|purgeData|scheduleForDeletion',
      flags: 'g',
      explanation:
        'Detects source files that manipulate persistent entities but contain no reference to lifecycle management constructs, indicating that data state transitions are not modelled.',
    },
    remediation:
      'Introduce a `DataLifecycleManager` class with states: `ACTIVE`, `ARCHIVED`, `PENDING_DELETION`, and `DELETED`. Attach lifecycle metadata to every personal data entity. Implement transition guards that prevent skipping states and emit audit events on each transition. Schedule background workers to advance data through lifecycle stages based on the retention schedule.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p4-005',
    criteria: 'P4.2',
    category: 'privacy',
    title: 'No Automated Data Expiration',
    description:
      'Database schema and application code show no automated expiration mechanism for personal data records. Without TTL fields, scheduled purge jobs, or database-level expiry, data accumulates indefinitely, violating the data minimisation and storage limitation principles of P4.2.',
    severity: 'high',
    languages: ['any'],
    targets: ['schema', 'source'],
    pattern: {
      type: 'regex',
      value:
        'CREATE\\s+TABLE\\s+\\w+\\s*\\([^;]*\\)(?![\\s\\S]{0,1200}(?:expires_at|expiry_date|expiration_date|\\bttl\\b|time_to_live|delete_at|purge_at|scheduled_deletion|expiresAt|expiryDate|expirationDate|deleteAt|purgeAt|scheduledDeletion))',
      flags: 'gi',
      explanation:
        'Detects CREATE TABLE statements whose column list does not contain any expiration, TTL, or scheduled-deletion column, indicating that no automated expiration is modelled at the data layer.',
    },
    remediation:
      'Add an `expires_at TIMESTAMPTZ` column to all tables storing personal data. Populate this column at insert time by adding the applicable retention period to `NOW()`. Create a scheduled job (cron or cloud scheduler) that runs nightly to hard-delete or anonymise rows where `expires_at <= NOW()`. For NoSQL stores, configure native TTL indexes.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p4-006',
    criteria: 'P4.2',
    category: 'privacy',
    title: 'Missing Retention Policy Per Data Type',
    description:
      'A single blanket retention period is applied to all data rather than per-data-type policies. Different personal data categories (health, financial, authentication logs, marketing preferences) carry distinct legal retention obligations that must be tracked individually under P4.2.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python'],
    targets: ['source', 'config'],
    pattern: {
      type: 'regex',
      value:
        '(?:retentionDays|retention_days|retentionPeriod|retention_period)\\s*[=:]\\s*\\d+(?![\\s\\S]{0,2000}(?:health|financial|payment|auth|marketing|biometric|location)\\s*[=:][\\s\\S]{0,200}(?:retentionDays|retention_days|retentionPeriod|retention_period))',
      flags: 'gi',
      explanation:
        'Detects a single numeric retention constant without evidence of separate per-category retention values for sensitive data types such as health, financial, or biometric data.',
    },
    remediation:
      'Create a `RetentionPolicy` map keyed by `DataCategory` enum values. Define distinct periods for: `HEALTH` (as required by HIPAA/local law), `FINANCIAL` (7 years), `AUTHENTICATION_LOGS` (90 days), `MARKETING` (duration of consent), `BIOMETRIC` (per consent or 3 years). Enforce the map in the data lifecycle manager so that the correct period is selected automatically when personal data is persisted.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p4-007',
    criteria: 'P4.2',
    category: 'privacy',
    title: 'No Legal Hold Mechanism',
    description:
      'The system lacks a legal hold (litigation hold) implementation that would prevent personal data from being purged while subject to a legal proceeding, investigation, or regulatory inquiry. Deleting data under legal hold exposes the organisation to spoliation sanctions.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'legalHold|legal_hold|litigationHold|litigation_hold|holdStatus|hold_status|onHold|on_hold|preservationOrder',
      flags: 'g',
      explanation:
        'Detects source files that implement deletion or purge routines but contain no reference to legal hold checks, indicating that automated deletion may remove data that should be preserved.',
    },
    remediation:
      'Implement a `LegalHoldService` with methods `placeHold(entityId, reason, authorisedBy)` and `releaseHold(entityId, authorisedBy)`. Store hold status in a dedicated `legal_holds` table. Modify all deletion, anonymisation, and archival workers to query this table before processing each record. Records under an active hold must be skipped and the skip must be logged.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p4-008',
    criteria: 'P4.2',
    category: 'privacy',
    title: 'Missing Retention Exception Process',
    description:
      'No exception workflow exists to handle cases where standard retention periods must be overridden (e.g., extended retention for fraud investigation, shortened retention by data subject request). Without a controlled exception process, ad-hoc deviations are untracked and ungoverned.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'retentionException|retention_exception|overrideRetention|override_retention|extendRetention|extend_retention|retentionOverride',
      flags: 'g',
      explanation:
        'Detects source files within retention management modules that lack any retention exception or override construct, implying exceptions are handled informally or not at all.',
    },
    remediation:
      'Create a `RetentionExceptionService` that accepts an exception request with fields: `entityId`, `dataCategory`, `requestedPeriod`, `justification`, `approvedBy`, and `expiresAt`. Require dual approval from a privacy officer and legal counsel for extensions. Record all exceptions in an immutable audit log. Set a maximum extension duration and enforce review on expiry.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p4-009',
    criteria: 'P4.2',
    category: 'privacy',
    title: 'No Data Archival Before Deletion',
    description:
      'Personal data is hard-deleted without a prior archival step. This prevents satisfying subject access requests, audit requirements, or legal hold obligations that may arise after deletion. P4.2 requires controlled disposal that accounts for all downstream obligations.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '\\.(?:delete|remove|destroy)\\s*\\([^)]*\\)(?![\\s\\S]{0,500}(?:archiv|backup|snapshot|cold_storage|coldStorage|glacierUpload|archivalService|archiveRecord))',
      flags: 'gi',
      explanation:
        'Detects delete, remove, or destroy method calls that are not preceded within a reasonable code proximity by an archival, backup, or cold-storage operation.',
    },
    remediation:
      'Implement an `ArchivalService` that serialises the data record to an immutable archive store (e.g., encrypted S3 Glacier or equivalent) before any deletion. The deletion routine must call `archivalService.archive(record)` and await confirmation before proceeding. Verify the archive checksum before committing the deletion. Retain archives for the minimum legally required period.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p4-010',
    criteria: 'P4.2',
    category: 'privacy',
    title: 'Missing Retention Audit',
    description:
      'Retention-related operations (archival, deletion, expiration, exception grants) are not written to an audit trail. Without an auditable record of retention activity, it is impossible to demonstrate compliance with retention obligations during a SOC 2 audit or regulatory review.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'retentionAudit|retention_audit|auditRetention|audit_retention|logRetentionEvent|log_retention_event|retentionLog|retention_log',
      flags: 'g',
      explanation:
        'Detects source files that implement retention operations but contain no reference to retention-specific audit logging, indicating that these operations leave no auditable evidence.',
    },
    remediation:
      'Instrument every retention lifecycle event with a structured audit log entry including: `eventType` (ARCHIVED, DELETED, EXCEPTION_GRANTED, HOLD_PLACED, HOLD_RELEASED), `entityId`, `dataCategory`, `actorId`, `timestamp`, and `reason`. Write these entries to an immutable, append-only audit store. Expose a retention audit report in the privacy dashboard and include it in SOC 2 evidence packages.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p4-011',
    criteria: 'P4.1',
    category: 'privacy',
    title: 'Data Retained Beyond Stated Purpose',
    description:
      'Personal data records persist in the database after the stated purpose has been fulfilled (e.g., completed transaction, expired subscription, withdrawn consent) with no automated mechanism to trigger disposal. Retaining data beyond its purpose violates P4.1 and P4.2 as well as storage limitation principles.',
    severity: 'critical',
    languages: ['any'],
    targets: ['schema'],
    pattern: {
      type: 'regex',
      value:
        "(?:status|state)\\s+(?:VARCHAR|TEXT|ENUM|character\\s+varying)(?:[^;]{0,300})(?:'completed'|'cancelled'|'terminated'|'expired'|'unsubscribed'|'withdrawn')(?![\\s\\S]{0,800}(?:expires_at|delete_at|purge_at|scheduled_for_deletion|retentionEnd|retention_end))",
      flags: 'gi',
      explanation:
        'Detects schema definitions that include terminal status enum literals (completed, cancelled, terminated) but lack any corresponding expiry or scheduled-deletion column, indicating that records in terminal states are never automatically cleared.',
    },
    remediation:
      'Add a `purpose_fulfilled_at` and `scheduled_deletion_at` column to each table storing personal data. Trigger population of `scheduled_deletion_at` via a database trigger or application event whenever status transitions to a terminal value. Implement a nightly purge job that processes all rows where `scheduled_deletion_at <= NOW()` and the legal hold flag is false.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p4-012',
    criteria: 'P4.1',
    category: 'privacy',
    title: 'No Use Limitation Enforcement',
    description:
      'The application exposes personal data through APIs or internal services without enforcing use-limitation controls. Any authenticated caller can request any personal data field regardless of whether the requesting service or user role has a legitimate, disclosed purpose for that data.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:router|app|server|controller|handler)\\s*\\.(?:get|post|put|patch|delete)\\s*\\([^)]*(?:user|customer|profile|personal|pii)[^)]*\\)\\s*(?:,|=>|\\{)(?![\\s\\S]{0,400}(?:useLimitation|checkPurpose|purposeGuard|dataUsePolicy|allowedPurpose|UseLimitationMiddleware))',
      flags: 'gi',
      explanation:
        'Detects route or handler definitions for personal data endpoints that lack use-limitation middleware or purpose-check guards, indicating that access is gated only on authentication, not on disclosed purpose.',
    },
    remediation:
      'Create a `UseLimitationMiddleware` that intercepts all requests to personal data endpoints and validates: (1) the requesting service is registered with an approved purpose, (2) the requested data fields are within that purpose scope, (3) a valid legal basis exists at the time of the request. Reject and log requests that fail validation. Apply the middleware globally to all routes under the `/personal-data` namespace.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p4-013',
    criteria: 'P4.1',
    category: 'privacy',
    title: 'Missing Profiling Opt-Out',
    description:
      'The application performs profiling (behavioural analysis, scoring, segmentation) on personal data without providing data subjects with a mechanism to opt out. GDPR Article 21 and similar regulations grant the right to object to profiling, and P4.1 requires honouring stated choices regarding data use.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:profile|segment|score|rank|cluster|classify)(?:User|Customer|Subject|Person|Individual|Profile)\\s*\\([^)]*\\)(?![\\s\\S]{0,600}(?:profilingOptOut|profiling_opt_out|checkProfilingConsent|allowProfiling|profilingEnabled|optedOutOfProfiling))',
      flags: 'gi',
      explanation:
        'Detects calls to profiling or scoring functions that do not check a profiling opt-out or consent flag before executing, indicating that opt-out preferences are not honoured.',
    },
    remediation:
      "Before every profiling operation, query the consent store for the subject's `profilingOptOut` flag. If `true`, skip the profiling operation and return a default or neutral result. Expose an opt-out endpoint (`POST /preferences/profiling-opt-out`) and honour it within 24 hours. Sync opt-out preferences to all downstream profiling services via an event bus.",
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p4-014',
    criteria: 'P4.1',
    category: 'privacy',
    title: 'No Automated Decision-Making Disclosure',
    description:
      'The application makes automated decisions with significant effects on data subjects (credit scoring, content moderation, access denial) without notifying the affected individual or providing an explanation. GDPR Article 22 and P4.1 require disclosure of automated decision-making and the right to human review.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:autoDecision|auto_decision|automatedDecision|automated_decision|mlDecision|ml_decision|ruleEngine|rule_engine|scoreDecision|score_decision)\\s*(?:[=(]|\\basync\\b)[^;\\n]{0,300}(?:deny|reject|block|approve|grant|flag|suspend|terminate)',
      flags: 'gi',
      explanation:
        'Detects automated decision functions that produce consequential outcomes (deny, reject, block, approve, suspend) without evidence of a disclosure or notification call in the same scope.',
    },
    remediation:
      'Wrap all automated decision outputs in an `AutomatedDecisionRecord` that includes: `decisionId`, `subjectId`, `decisionType`, `outcome`, `confidence`, `factors` (sanitised), `timestamp`, and `reviewAvailable`. Send a notification to the data subject via their registered channel within the same transaction. Implement a `POST /decisions/{id}/review` endpoint to route disputes to a human reviewer.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p4-015',
    criteria: 'P4.1',
    category: 'privacy',
    title: 'Missing Data Use Audit Trail',
    description:
      'Personal data access and use events are not written to a dedicated audit trail. Without a complete record of who accessed what personal data, when, and for what purpose, it is impossible to detect misuse, respond to subject access requests, or demonstrate compliance during audits.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'dataUseAudit|data_use_audit|auditDataAccess|audit_data_access|logDataUse|log_data_use|recordDataAccess|record_data_access|privacyAuditLog|privacy_audit_log',
      flags: 'g',
      explanation:
        'Detects source files that contain personal data read or query operations but lack any call to a data-use audit logging function, indicating that access events are not recorded.',
    },
    remediation:
      'Implement a `DataUseAuditService` that is called for every personal data access. Log: `accessorId`, `accessorRole`, `accessorService`, `dataSubjectId`, `dataCategories`, `fields`, `purpose`, `legalBasis`, `timestamp`, and `correlationId`. Write to an append-only, tamper-evident log store. Surface this data in the privacy dashboard and include it in DSR (Data Subject Request) responses.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p4-016',
    criteria: 'P4.3',
    category: 'privacy',
    title: 'No Cross-Purpose Data Access Controls',
    description:
      'Service-to-service or role-based access controls do not enforce purpose boundaries, allowing a service operating under one disclosed purpose (e.g., billing) to query data collected for a different purpose (e.g., product analytics). This cross-purpose leakage violates P4.1 and P4.3.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java'],
    targets: ['source', 'config'],
    pattern: {
      type: 'regex',
      value:
        '(?:hasRole|hasPermission|isAuthorized|checkAccess|canAccess|authorize)\\s*\\([^)]*(?:READ|WRITE|ADMIN|FULL)[^)]*\\)(?![\\s\\S]{0,400}(?:purpose|dataUse|allowedScope|withinScope|purposeCheck|crossPurpose|purposePolicy))',
      flags: 'gi',
      explanation:
        'Detects authorisation checks based solely on role or permission level without any accompanying purpose-scope validation, indicating that cross-purpose access is possible for any authorised role.',
    },
    remediation:
      'Extend the authorisation model to include a purpose dimension. Access control decisions must evaluate: `(role, permission) AND (requestedPurpose IN subject.consentedPurposes) AND (requestedPurpose IN service.declaredPurposes)`. Implement this as a policy in your authorisation service (OPA, Casbin, or equivalent). Define purpose boundaries in a machine-readable policy file and validate changes through a privacy review gate in CI.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p4-017',
    criteria: 'P4.3',
    category: 'privacy',
    title: 'Missing Data Sharing Agreements',
    description:
      'Personal data is shared with third parties or sub-processors without evidence of a data sharing agreement (DSA), data processing agreement (DPA), or standard contractual clauses (SCCs). P4.3 requires that personal data disclosed to third parties is subject to privacy commitments equivalent to those made to the data subject.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'config'],
    pattern: {
      type: 'semgrep',
      value: `rules:
  - id: missing-data-sharing-agreement
    patterns:
      - pattern-either:
          - pattern: $CLIENT.post($URL, $DATA, ...)
          - pattern: $CLIENT.put($URL, $DATA, ...)
          - pattern: fetch($URL, {method: "POST", body: $DATA, ...})
          - pattern: axios.post($URL, $DATA, ...)
      - pattern-not-inside: |
          if ($AGREEMENT_CHECK) { ... }
      - metavariable-regex:
          metavariable: $URL
          regex: .*(partner|vendor|external|third.?party|subprocessor).*
    message: Data transmission to external party without data sharing agreement check
    languages: [typescript, javascript, python]
    severity: ERROR`,
      explanation:
        'Detects HTTP POST or PUT calls directed at URLs containing partner, vendor, external, or third-party path segments that are not wrapped in a data-agreement validation guard.',
    },
    remediation:
      'Maintain a `ThirdPartyRegistry` that maps each external recipient to their DPA/DSA document reference, data categories permitted, and legal basis. Before any data transmission to a third party, query the registry to confirm an active agreement covers the data categories being shared. Reject and alert on transmissions to unregistered recipients. Run a quarterly review of the registry.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p4-018',
    criteria: 'P4.3',
    category: 'privacy',
    title: 'No Data Use Impact Assessment',
    description:
      'New features or data processing activities that involve significant privacy risk are introduced without a Data Protection Impact Assessment (DPIA) or Privacy Impact Assessment (PIA). P4.3 requires that the impact of new or changed data uses is evaluated before deployment to identify and mitigate privacy risks.',
    severity: 'medium',
    languages: ['any'],
    targets: ['cicd'],
    pattern: {
      type: 'absence',
      value:
        'dpia|pia|privacy.?impact|data.?protection.?impact|privacyAssessment|privacy_assessment|impactAssessment|impact_assessment',
      flags: 'gi',
      explanation:
        'Detects CI/CD pipeline configurations that deploy to production without any step referencing a DPIA/PIA gate, checklist, or approval workflow, indicating that privacy impact is not assessed as part of the release process.',
    },
    remediation:
      'Add a DPIA gate to the CI/CD pipeline that triggers automatically when a pull request modifies files in directories containing personal data processing logic (e.g., `src/data`, `src/analytics`, `migrations/`). The gate should require a completed DPIA checklist (stored as `dpia.yaml` in the repo root) to be approved by the privacy officer before the pipeline proceeds to deployment. Archive completed DPIAs with the release artefacts.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
      'https://www.nist.gov/cyberframework',
    ],
  },
];
