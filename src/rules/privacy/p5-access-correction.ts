/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const p5Rules: ISoc2Rule[] = [
  {
    id: 'p5-001',
    criteria: 'P5.1',
    category: 'privacy',
    title: 'Missing Data Subject Access Request (DSAR) Endpoint',
    description:
      'The application does not expose a dedicated endpoint for data subject access requests. Privacy regulations such as GDPR Article 15 and CCPA require organizations to provide individuals with the ability to request access to their personal data. Without a DSAR endpoint, data subjects have no programmatic mechanism to exercise their right of access.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        '(?i)(dsar|data[_\\-\\s]?subject[_\\-\\s]?access|access[_\\-\\s]?request|privacy[_\\-\\s]?request|subject[_\\-\\s]?request)',
      flags: 'i',
      explanation:
        'Checks for the absence of any route, controller, or handler that references DSAR or data subject access request patterns. If no match is found in the source file the rule triggers.',
    },
    remediation:
      'Implement a dedicated DSAR endpoint (e.g., POST /api/privacy/access-request) that accepts authenticated requests, logs the request with a timestamp, and initiates fulfillment within the legally required timeframe (typically 30 days). The endpoint must verify the requester identity before processing.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p5-002',
    criteria: 'P5.1',
    category: 'privacy',
    title: 'No Identity Verification for DSAR',
    description:
      'Data subject access request handlers lack identity verification logic. Responding to a DSAR without first verifying the requester identity can expose personal data to unauthorized parties. GDPR Recital 64 and NIST SP 800-53 IA-12 require reasonable steps to verify identity before disclosing personal data.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(dsar|access[_\\-\\s]?request|privacy[_\\-\\s]?request)[^}]{0,500}(?!verif|authenticate|identity|id[_\\-\\s]?check|mfa|two[_\\-\\s]?factor)',
      flags: 'i',
      explanation:
        'Detects DSAR-related handlers that do not contain identity verification calls (verif*, authenticate, identity check, MFA) within the same logical block, indicating the requester is not authenticated before data is returned.',
    },
    remediation:
      'Before fulfilling any DSAR, require the requester to complete a verified authentication step such as email OTP, government ID match, or re-authentication with MFA. Log the verification method and outcome alongside the DSAR record. Reject requests that fail verification and notify the requester securely.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p5-003',
    criteria: 'P5.1',
    category: 'privacy',
    title: 'Missing DSAR Response Time Tracking',
    description:
      'DSAR handlers do not record a deadline or track the elapsed time since the request was submitted. GDPR Article 12 mandates a response within one calendar month (extendable to three). Without timestamp tracking and deadline enforcement, organizations cannot demonstrate compliance with statutory response windows and risk regulatory penalties.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(dsar|access[_\\-\\s]?request|privacy[_\\-\\s]?request)[^}]{0,600}(?!deadline|due[_\\-\\s]?date|expires?[_\\-\\s]?at|response[_\\-\\s]?by|sla|thirty[_\\-\\s]?day|30[_\\-\\s]?day)',
      flags: 'i',
      explanation:
        'Detects DSAR-related code blocks that do not store or reference a deadline, due date, expiry timestamp, or SLA field, indicating response time is not being tracked.',
    },
    remediation:
      'On receipt of a DSAR, persist a `receivedAt` timestamp and a computed `dueBy` timestamp (receivedAt + 30 days). Implement a scheduled job that alerts privacy officers when a DSAR approaches its deadline. Expose a status endpoint so requesters can query progress.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p5-004',
    criteria: 'P5.1',
    category: 'privacy',
    title: 'No Data Portability Export (JSON/CSV)',
    description:
      'The application does not provide a structured, machine-readable export of personal data in response to DSAR or portability requests. GDPR Article 20 grants data subjects the right to receive their data in a commonly used, machine-readable format. Providing only human-readable summaries does not satisfy this requirement.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        '(export[_\\-\\s]?json|export[_\\-\\s]?csv|to[_\\-\\s]?csv|to[_\\-\\s]?json|application\\/json|text\\/csv|data[_\\-\\s]?export|portability)',
      flags: 'i',
      explanation:
        'Checks for the absence of JSON or CSV export logic, content-type headers, or portability-related identifiers. If none are present the rule flags the file as lacking data portability support.',
    },
    remediation:
      'Implement a data export function that serializes all personal data held for a given subject into a structured JSON or CSV package. Include all profile fields, transaction history, consent records, and any derived data. Deliver the package via a secure, time-limited download link and log the export event.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p5-005',
    criteria: 'P5.2',
    category: 'privacy',
    title: 'Missing Correction Request Mechanism',
    description:
      'The application provides no API endpoint or UI pathway for data subjects to submit correction or rectification requests. GDPR Article 16 establishes the right to rectification of inaccurate personal data without undue delay. Without a correction mechanism, data subjects cannot exercise this right, exposing the organization to regulatory and reputational risk.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        '(correct(ion)?[_\\-\\s]?request|rectif(y|ication)|amend[_\\-\\s]?request|update[_\\-\\s]?request[_\\-\\s]?privacy|data[_\\-\\s]?correction)',
      flags: 'i',
      explanation:
        'Checks for the absence of correction, rectification, or amendment request handling code. If no matching identifiers exist the file lacks a correction request mechanism.',
    },
    remediation:
      'Create a PATCH or PUT endpoint (e.g., /api/privacy/correction-request) that accepts the data subject identifier, the field(s) to be corrected, the proposed new values, and supporting evidence. Queue the request for human or automated review before applying changes to production data.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p5-006',
    criteria: 'P5.2',
    category: 'privacy',
    title: 'No Correction Audit Trail',
    description:
      'Data corrections applied through privacy request workflows are not written to an immutable audit log. AICPA P5.2 and NIST SP 800-53 AU-9 require that all changes to personal data records be traceable to an initiating request, an operator identity, a timestamp, and the before/after state. Without an audit trail, organizations cannot demonstrate accountability for data changes.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(correct(ion)?|rectif|amend)[^}]{0,400}(?!audit|log|trail|history|before|after|previous[_\\-\\s]?value|old[_\\-\\s]?value)',
      flags: 'i',
      explanation:
        'Detects correction or rectification code paths that do not invoke audit logging, history recording, or before/after value capture, suggesting changes are applied without a traceable record.',
    },
    remediation:
      'Before applying any correction, snapshot the current field value(s) and write an audit record containing: request ID, subject ID, field name, old value, new value, operator/system identity, and ISO-8601 timestamp. Store audit records in an append-only data store separate from the primary database.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p5-007',
    criteria: 'P5.1',
    category: 'privacy',
    title: 'Missing Data Completeness in Exports',
    description:
      'Data export routines for DSAR fulfillment do not include all categories of personal data held by the system such as logs, derived attributes, or third-party integrations. Incomplete exports violate GDPR Article 15(3) and can constitute a partial non-response. Data subjects must receive all personal data processed about them, not only primary profile fields.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'semgrep',
      value: [
        'rules:',
        '  - id: p5-007-incomplete-export',
        '    patterns:',
        '      - pattern: |',
        '          function $EXPORT(...) { ... }',
        '      - pattern-not: |',
        '          function $EXPORT(...) {',
        '            ...',
        '            $LOGS = ...',
        '            ...',
        '          }',
        '      - pattern-not: |',
        '          function $EXPORT(...) {',
        '            ...',
        '            $DERIVED = ...',
        '            ...',
        '          }',
        '    message: >',
        '      Data export function may not include all personal data categories such as',
        '      logs or derived attributes.',
        '    languages: [javascript, typescript]',
        '    severity: WARNING',
      ].join('\n'),
      explanation:
        'Semgrep rule that flags export functions lacking log or derived-data collection, indicating the export may be incomplete relative to all personal data held.',
    },
    remediation:
      'Maintain a data inventory mapping every personal data category (profile, logs, analytics, derived scores, third-party synced fields) to its storage location. The export pipeline must query each source and merge results into a single comprehensive package before delivering the DSAR response.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p5-008',
    criteria: 'P5.2',
    category: 'privacy',
    title: 'No Third-Party Notification of Corrections',
    description:
      'When personal data is corrected in response to a data subject request, downstream third-party processors and sub-processors that received the original data are not notified of the correction. GDPR Article 19 requires controllers to communicate rectification to each recipient to whom personal data was disclosed. Failure to notify creates inconsistent data lineage across the data ecosystem.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(correct(ion)?|rectif)[^}]{0,500}(?!notif(y|ication)|third[_\\-\\s]?party|downstream|recipient|propagat|broadcast|webhook|callback)',
      flags: 'i',
      explanation:
        'Detects correction handling code that does not include notification, propagation, or webhook calls to third-party recipients, suggesting downstream data remains uncorrected.',
    },
    remediation:
      'Maintain a recipient registry recording every third party to which personal data has been disclosed. After applying a correction, iterate the registry and dispatch correction notifications via a reliable message queue. Log each notification attempt and confirmation. Retry on failure and escalate undelivered notifications.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p5-009',
    criteria: 'P5.1',
    category: 'privacy',
    title: 'Missing DSAR Rate Limiting (Abuse Prevention)',
    description:
      'DSAR endpoints lack rate limiting controls, allowing a single user or malicious actor to submit an unbounded volume of access requests. While privacy rights are legitimate, uncontrolled request floods can be used to extract large amounts of data incrementally, degrade service availability, or exhaust operator resources. NIST SP 800-53 SI-10 and SC-5 require input validation and denial-of-service protections on all public-facing endpoints.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(dsar|access[_\\-\\s]?request|privacy[_\\-\\s]?request)[^}]{0,500}(?!rate[_\\-\\s]?limit|throttl|ratelimit|too[_\\-\\s]?many|429|quota|cooldown|backoff)',
      flags: 'i',
      explanation:
        'Detects DSAR route or handler code that does not reference rate limiting middleware, throttling, HTTP 429, or quota controls, indicating the endpoint is unprotected against request flooding.',
    },
    remediation:
      'Apply rate limiting middleware to DSAR endpoints, restricting each authenticated identity to a reasonable number of requests per rolling window (e.g., 5 requests per 30 days). Return HTTP 429 with a Retry-After header when the limit is exceeded. Log rate limit events and alert on anomalous submission volumes.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p5-010',
    criteria: 'P5.1',
    category: 'privacy',
    title: 'No Partial Access Controls (Redact Third-Party Data)',
    description:
      'DSAR data exports do not redact or mask personal data belonging to third parties that appears in the requester data set. For example, a messaging thread export may include the personal data of other users. GDPR Article 15(4) explicitly states that access rights must not adversely affect the rights and freedoms of others. Without redaction logic, exports can constitute unauthorized disclosure.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(export|dsar|access[_\\-\\s]?request)[^}]{0,600}(?!redact|mask|anonymi[sz]|scrub|sanitize|third[_\\-\\s]?party[_\\-\\s]?filter|other[_\\-\\s]?user)',
      flags: 'i',
      explanation:
        'Detects export and DSAR code paths that do not include redaction, masking, or anonymisation of third-party personal data before returning results to the requester.',
    },
    remediation:
      'Implement a redaction layer in the export pipeline that identifies data fields originating from or relating to third-party individuals and replaces them with anonymised tokens or removes them entirely. Document the redaction logic and ensure it is applied consistently across all export formats (JSON, CSV, PDF).',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p5-011',
    criteria: 'P5.1',
    category: 'privacy',
    title: 'Missing Automated DSAR Fulfillment',
    description:
      'DSAR processing relies entirely on manual operator steps with no automation for data collection, packaging, or delivery. Fully manual workflows introduce delays, human error, and inconsistent responses. AICPA P5.1 expects that organizations implement reliable processes for responding to access requests. Automation reduces the risk of missed deadlines and incomplete responses at scale.',
    severity: 'low',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        '(auto(mat(e|ic|ed|ion))?[_\\-\\s]?dsar|dsar[_\\-\\s]?auto|fulfill[_\\-\\s]?request|process[_\\-\\s]?dsar|dsar[_\\-\\s]?pipeline|dsar[_\\-\\s]?job|dsar[_\\-\\s]?worker|dsar[_\\-\\s]?queue)',
      flags: 'i',
      explanation:
        'Checks for the absence of automated DSAR processing identifiers such as queue workers, pipeline functions, or scheduled jobs. Absence suggests fulfillment is handled manually.',
    },
    remediation:
      'Build an automated DSAR fulfillment pipeline using a message queue or workflow engine. On receipt of a verified DSAR, trigger an asynchronous job that queries all data stores, assembles the export, redacts third-party data, and delivers the result to the requester. Reserve manual review only for edge cases flagged by the automation.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p5-012',
    criteria: 'P5.1',
    category: 'privacy',
    title: 'No DSAR Status Tracking',
    description:
      'There is no mechanism for data subjects or privacy officers to query the current status of an in-flight DSAR (e.g., received, verifying identity, processing, fulfilled, denied). GDPR Article 12(3) requires that data subjects be informed of actions taken on their request within one month. Without a status-tracking system, requesters cannot obtain progress updates and controllers cannot demonstrate timely processing.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        '(dsar[_\\-\\s]?status|request[_\\-\\s]?status|access[_\\-\\s]?request[_\\-\\s]?status|privacy[_\\-\\s]?request[_\\-\\s]?status|status[_\\-\\s]?dsar|fulfillment[_\\-\\s]?status)',
      flags: 'i',
      explanation:
        'Checks for the absence of DSAR status tracking identifiers. If no status fields, enums, or status-query endpoints are present the file lacks DSAR progress visibility.',
    },
    remediation:
      'Add a `status` field to the DSAR record using a state machine with values such as RECEIVED, IDENTITY_VERIFIED, PROCESSING, AWAITING_REVIEW, FULFILLED, DENIED, and EXPIRED. Expose a GET endpoint that allows the authenticated requester to check status using a reference token issued at submission. Send email notifications on each state transition.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p5-013',
    criteria: 'P5.2',
    category: 'privacy',
    title: 'Missing Suppression List for Deleted Users',
    description:
      'After a deletion or erasure request is fulfilled the system does not maintain a suppression list to prevent re-import or re-creation of the deleted subject record. Without a suppression mechanism, data can re-enter the system through third-party syncs, CRM imports, or analytics pipelines, effectively undoing the erasure. GDPR Article 17 and AICPA P5.2 require that erasure be durable and that systems prevent inadvertent re-processing of erased data.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        '(suppression[_\\-\\s]?list|suppress(ed)?[_\\-\\s]?user|do[_\\-\\s]?not[_\\-\\s]?(re)?import|delet(ed)?[_\\-\\s]?subject[_\\-\\s]?list|erasure[_\\-\\s]?registry|blocklist|deny[_\\-\\s]?list[_\\-\\s]?user)',
      flags: 'i',
      explanation:
        'Checks for the absence of suppression list, erasure registry, or blocklist identifiers. Absence indicates deleted user identifiers are not being tracked to prevent re-creation.',
    },
    remediation:
      'Maintain an erasure registry (suppression list) that stores a one-way hash of deleted subject identifiers (e.g., hashed email). On every import, sync, or account creation flow, check the candidate identifier against the suppression list before inserting. Reject or quarantine matches and alert the privacy team. Retain suppression records for the duration required by applicable law.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
];
