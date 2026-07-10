/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const p6Rules: ISoc2Rule[] = [
  {
    id: 'p6-001',
    criteria: 'P6.1',
    category: 'privacy',
    title: 'Missing Data Processing Agreement Enforcement',
    description:
      'Third-party integrations and service calls must reference or enforce a Data Processing Agreement (DPA). Code that invokes external processors without DPA validation exposes personal data to uncontrolled handling and violates P6.1 obligations.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value: 'dpa|dataProcessingAgreement|data_processing_agreement|processingAgreement|DPA_SIGNED',
      flags: 'i',
      explanation:
        'Detects source files that call third-party HTTP endpoints or SDKs but contain no reference to a DPA identifier, constant, or validation function.',
    },
    remediation:
      'Before invoking any third-party data processor, assert that a signed DPA is on file and inject a DPA reference constant (e.g., `DPA_SIGNED = true`) checked at runtime. Gate all processor initialisation behind this check and document the DPA version in your vendor register.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p6-002',
    criteria: 'P6.1',
    category: 'privacy',
    title: 'No Third-Party Data Transfer Logging',
    description:
      'Every transfer of personal data to a third party must be logged with a timestamp, recipient identity, data categories transferred, and legal basis. Absence of such logging prevents auditors from verifying P6.1 compliance and makes breach investigation unreliable.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:axios\\.(?:post|put|patch)|fetch\\(|http\\.(?:post|put|patch)|requests\\.(?:post|put|patch)|HttpClient|WebClient|RestTemplate)(?:(?!transferLog|dataTransferLog|logTransfer|auditTransfer|recordTransfer).){0,400}(?:personalData|pii|userData|user_data|customerData|customer_data)',
      flags: 'is',
      explanation:
        'Matches HTTP client calls that reference personal-data variables without a corresponding transfer-log call in the same code block, indicating undocumented third-party disclosures.',
    },
    remediation:
      'Wrap every outbound personal-data transfer in a logging decorator or middleware that records: ISO-8601 timestamp, recipient name/URL, data categories, lawful basis, and transaction ID. Store logs in an append-only audit store for a minimum of 7 years.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p6-003',
    criteria: 'P6.2',
    category: 'privacy',
    title: 'Missing Cross-Border Transfer Safeguards',
    description:
      'Transferring personal data across national borders without documented safeguards (SCCs, BCRs, adequacy decision, or derogation) violates P6.2. Code that configures cloud storage, CDN, or database replication to regions outside the originating country must assert a legal transfer mechanism.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source', 'config', 'iac'],
    pattern: {
      type: 'regex',
      value:
        '(?:region|replication_region|replica_region|storageLocation|storage_location|bucketRegion)\\s*[=:]\\s*["\'](?:us-|eu-|ap-|sa-|af-|me-)[a-z0-9-]+["\'](?:(?!crossBorderSafeguard|transfer_mechanism|scc|standardContractualClause|bcr|adequacyDecision|adequacy_decision).){0,600}',
      flags: 'is',
      explanation:
        'Detects region assignments in configuration and IaC files where no cross-border transfer safeguard constant or comment is present within the same configuration block.',
    },
    remediation:
      'For each cross-border data flow, explicitly declare the applicable transfer mechanism (e.g., `transferMechanism: "SCC-2021"`) adjacent to the region configuration. Validate the declared mechanism against an allowlist at deployment time via a CI policy check.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p6-004',
    criteria: 'P6.2',
    category: 'privacy',
    title: 'No Standard Contractual Clauses Reference',
    description:
      'Standard Contractual Clauses (SCCs) are a primary GDPR-compliant mechanism for cross-border transfers. Configuration and infrastructure files that route personal data internationally must reference the applicable SCC version to demonstrate a valid legal basis under P6.2.',
    severity: 'high',
    languages: ['any'],
    targets: ['config', 'iac'],
    pattern: {
      type: 'absence',
      value: 'scc|standardContractualClause|standard_contractual_clause|SCC_VERSION|scc_version',
      flags: 'i',
      explanation:
        'Detects IaC and configuration files that define cross-region data stores or replicas but contain no SCC version reference, indicating missing contractual safeguards for international transfers.',
    },
    remediation:
      'Add an `scc_version` tag or comment to every resource that stores or processes personal data and spans multiple jurisdictions (e.g., `scc_version = "EU-2021/914"`). Enforce presence of this tag via an OPA/Rego policy in CI.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p6-005',
    criteria: 'P6.2',
    category: 'privacy',
    title: 'Missing Adequacy Decision Checks',
    description:
      'When transferring personal data to a country covered by an adequacy decision, the application must verify that the decision is still in force at the time of transfer. Hard-coded country lists or skipped validation exposes the organisation to P6.2 violations if an adequacy decision is revoked.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        'adequacyDecision|adequacy_decision|adequacyCheck|adequacy_check|isAdequate|check_adequacy',
      flags: 'i',
      explanation:
        'Identifies the presence or absence of adequacy-decision validation calls. When combined with cross-border transfer logic lacking this identifier, it flags missing runtime adequacy checks.',
    },
    remediation:
      'Implement an `AdequacyDecisionService` that fetches or caches the current list of adequate countries from a trusted source (e.g., European Commission). Call `isAdequate(destinationCountry)` before each cross-border transfer and reject or reroute if the check fails.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p6-006',
    criteria: 'P6.1',
    category: 'privacy',
    title: 'No Data Sharing Register',
    description:
      'A data sharing register (also called a Record of Processing Activities for disclosures) must document every category of recipient, the data shared, the purpose, and the legal basis. Absence of a register reference in the codebase or configuration indicates this control is not implemented, violating P6.1.',
    severity: 'high',
    languages: ['any'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'dataSharingRegister|data_sharing_register|sharingRegister|sharing_register|ROPA|recordOfProcessing|record_of_processing',
      flags: 'i',
      explanation:
        'Detects that no data-sharing register reference exists anywhere in the source or configuration, indicating the control is missing rather than merely untested.',
    },
    remediation:
      'Create and maintain a machine-readable data sharing register (e.g., a JSON/YAML file under `compliance/data-sharing-register.json`). Reference the register ID in every module that discloses personal data and validate its completeness in CI using a schema linter.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p6-007',
    criteria: 'P6.3',
    category: 'privacy',
    title: 'Missing Recipient Disclosure to Data Subjects',
    description:
      'Data subjects must be informed of the categories of recipients to whom their personal data is disclosed. Privacy notice generation code or consent-management modules that do not include recipient disclosure violate P6.3 and erode individual rights.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:privacyNotice|privacy_notice|consentText|consent_text|cookiePolicy|cookie_policy|dataSubjectNotice)(?:(?!recipient|thirdPart|third_part|processor|controller|dataShare|data_share).){0,800}',
      flags: 'is',
      explanation:
        'Detects privacy-notice or consent-text generation functions that do not include a recipient or third-party disclosure section, indicating data subjects are not informed of disclosures.',
    },
    remediation:
      'Ensure every privacy notice and consent artifact includes a `recipients` section listing categories of third-party recipients. Render this section dynamically from the data sharing register so it stays current. Add an integration test that asserts the rendered notice contains the word "recipients".',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p6-008',
    criteria: 'P6.4',
    category: 'privacy',
    title: 'No Government Data Request Logging',
    description:
      'Requests for personal data from government or law-enforcement bodies must be logged and, where legally permissible, reported to data subjects or in transparency reports. Handling such requests without logging violates P6.4 accountability requirements.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:governmentRequest|government_request|lawEnforcementRequest|law_enforcement_request|legalRequest|legal_request|nationalSecurityRequest)(?:(?!log|audit|record|store|persist|track).){0,500}',
      flags: 'is',
      explanation:
        'Identifies functions or handlers named for government/law-enforcement requests that do not call a logging or audit function within 500 characters, indicating undocumented disclosures.',
    },
    remediation:
      'Create a `GovernmentRequestHandler` that automatically logs every request with: receipt timestamp, requesting authority, data categories requested, legal authority cited, data provided (yes/no), and response timestamp. Store records in an immutable log store. Assign a unique request ID for cross-referencing in transparency reports.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p6-009',
    criteria: 'P6.4',
    category: 'privacy',
    title: 'Missing Law Enforcement Request Policy',
    description:
      'The organisation must have a documented and code-enforced policy for handling law-enforcement data requests, including legal review steps, notification obligations, and gag-order procedures. P6.4 requires this to protect individual rights during compelled disclosures.',
    severity: 'high',
    languages: ['any'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'lawEnforcementPolicy|law_enforcement_policy|LERequestPolicy|le_request_policy|compelledDisclosurePolicy|compelled_disclosure_policy',
      flags: 'i',
      explanation:
        'Detects the absence of any law-enforcement request policy reference in source and configuration files, indicating the policy is not operationalised in code.',
    },
    remediation:
      'Implement a `LawEnforcementRequestPolicy` class or configuration file that enforces: mandatory legal-team review before response, gag-order flag to suppress notification, maximum response timeline, and automatic escalation on ambiguous requests. Reference the policy from all legal-request handlers.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p6-010',
    criteria: 'P6.4',
    category: 'privacy',
    title: 'No Transparency Report Mechanism',
    description:
      'Organisations must publish periodic transparency reports disclosing categories and volumes of government data requests. Absence of a transparency-report generation mechanism in the codebase means disclosures cannot be systematically tracked and reported, violating P6.4.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source', 'cicd'],
    pattern: {
      type: 'absence',
      value:
        'transparencyReport|transparency_report|generateTransparencyReport|generate_transparency_report|publishTransparencyReport|publish_transparency_report',
      flags: 'i',
      explanation:
        'Detects the absence of any transparency-report generation or publication function in source and CI/CD pipeline files, indicating the control is not implemented.',
    },
    remediation:
      'Build a `TransparencyReportService` that aggregates government request logs, anonymises counts per category, and generates a structured report (JSON + human-readable PDF). Schedule report generation in CI/CD and publish to the public transparency portal at least annually.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p6-011',
    criteria: 'P6.5',
    category: 'privacy',
    title: 'Missing Data Breach Notification to Regulators',
    description:
      'Upon discovering a personal data breach, the organisation must notify the relevant supervisory authority within the legally required window (typically 72 hours under GDPR). P6.5 requires code-level controls to detect, assess, and dispatch regulator notifications automatically.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:breach|dataBreach|data_breach|securityIncident|security_incident)(?:(?!notifyRegulator|notify_regulator|regulatorNotification|regulator_notification|supervisoryAuthority|supervisory_authority|dpaNotification|dpa_notification).){0,600}',
      flags: 'is',
      explanation:
        'Identifies breach or incident objects/handlers that lack a regulator-notification call, indicating the automatic notification control is absent.',
    },
    remediation:
      'Implement a `RegulatoryNotificationService` triggered on any breach classification. It must: validate breach severity, compose a structured notification (nature of breach, categories affected, approximate number of subjects, DPO contact, likely consequences, mitigation measures), and dispatch to the relevant DPA endpoint within 72 hours. Log the notification with a confirmation receipt.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p6-012',
    criteria: 'P6.5',
    category: 'privacy',
    title: 'No Data Breach Notification to Individuals',
    description:
      'When a breach is likely to result in a high risk to individuals, they must be notified without undue delay (P6.5). Code that handles breaches without an individual-notification pathway leaves affected persons uninformed and unable to protect themselves.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:breach|dataBreach|data_breach|securityIncident|security_incident)(?:(?!notifyIndividual|notify_individual|individualNotification|individual_notification|subjectNotification|subject_notification|notifyAffected|notify_affected).){0,600}',
      flags: 'is',
      explanation:
        'Detects breach or incident handlers that do not invoke an individual-notification function, indicating affected persons are not informed of high-risk breaches.',
    },
    remediation:
      'Add an `IndividualNotificationService` to the breach-response workflow. For each breach classified as high-risk, identify affected individuals from the incident record, compose a clear notification (what happened, data involved, steps taken, recommended actions, DPO contact), and dispatch via email or in-app message. Track delivery status and retry failures.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p6-013',
    criteria: 'P6.5',
    category: 'privacy',
    title: 'Missing 72-Hour Breach Notification Tracking',
    description:
      'Regulatory frameworks (e.g., GDPR Art. 33) mandate breach notification to supervisory authorities within 72 hours of becoming aware of a breach. Without automated tracking, organisations risk exceeding this deadline and incurring significant penalties. P6.5 requires demonstrable tracking.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:breach|dataBreach|data_breach)(?:(?!72[Hh]our|seventyTwoHour|seventy_two_hour|notificationDeadline|notification_deadline|breachTimer|breach_timer|slaDeadline|sla_deadline).){0,700}',
      flags: 'is',
      explanation:
        'Identifies breach objects or handlers that do not reference a 72-hour deadline timer or SLA tracking mechanism, indicating the notification deadline is not being enforced.',
    },
    remediation:
      'Implement a `BreachNotificationTimer` that starts a 72-hour countdown when a breach is first recorded. The timer must: send escalation alerts at 24h and 48h milestones, automatically draft a notification if none is submitted by 60h, and mark the breach as SLA-breached with a compliance flag if the 72h window is exceeded. Store all timestamps in the incident record.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p6-014',
    criteria: 'P6.5',
    category: 'privacy',
    title: 'No Breach Severity Classification',
    description:
      'Breach response priorities and notification obligations differ by severity. Without a classification scheme (e.g., low / medium / high / critical) applied at the time a breach is recorded, organisations cannot correctly determine notification obligations under P6.5 and risk either over- or under-reporting.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:breach|dataBreach|data_breach|incident|securityIncident)(?:(?!severity|classification|classify|riskLevel|risk_level|impactLevel|impact_level|breachCategory|breach_category).){0,500}',
      flags: 'is',
      explanation:
        'Detects breach or incident records and handlers that do not assign or reference a severity or risk-level field, indicating classification is missing from the breach workflow.',
    },
    remediation:
      'Define a `BreachSeverity` enum (LOW | MEDIUM | HIGH | CRITICAL) and require every breach record to include a `severity` field set by the triage function. Map severity levels to notification obligations: MEDIUM+ triggers regulator notification, HIGH+ triggers individual notification. Reject breach records that omit the severity field via schema validation.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p6-015',
    criteria: 'P6.6',
    category: 'privacy',
    title: 'Missing Breach Containment Procedures',
    description:
      'P6.6 requires that upon detecting a breach, immediate containment actions are taken to prevent further unauthorised access or disclosure. Code that logs or reports a breach but does not trigger containment actions (e.g., token revocation, session invalidation, account lockout) leaves the attack surface open.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(?:breach|dataBreach|data_breach|securityIncident)(?:(?!contain|revoke|invalidate|lockout|lock_out|quarantine|isolate|disable|suspend|block).){0,600}',
      flags: 'is',
      explanation:
        'Identifies breach or incident handlers that do not call a containment action (revocation, invalidation, lockout, quarantine, isolation), indicating the system does not automatically contain a breach.',
    },
    remediation:
      'Create a `BreachContainmentService` with actions for each breach type: revoke all active tokens for affected accounts, invalidate sessions, lock compromised service accounts, quarantine affected data stores, and enable enhanced monitoring. Invoke containment automatically upon breach classification and log each containment action with a timestamp.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p6-016',
    criteria: 'P6.6',
    category: 'privacy',
    title: 'No Post-Breach Remediation Tracking',
    description:
      'Following a breach, P6.6 requires documented remediation actions to prevent recurrence. Without a remediation-tracking mechanism, corrective measures may not be completed, verified, or auditable, leaving systemic vulnerabilities unaddressed.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'remediationPlan|remediation_plan|postBreachRemediation|post_breach_remediation|correctiveAction|corrective_action|remediationTracker|remediation_tracker',
      flags: 'i',
      explanation:
        'Detects the absence of any post-breach remediation tracking reference in source and configuration files, indicating corrective actions are not systematically managed.',
    },
    remediation:
      'Implement a `RemediationTracker` that creates a remediation plan for each closed breach, assigns owners to each action item, tracks completion status and deadlines, and triggers re-assessment when all items are closed. Link each remediation plan to its parent breach record by incident ID. Expose a compliance dashboard showing open vs. closed items.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p6-017',
    criteria: 'P6.7',
    category: 'privacy',
    title: 'Missing Disclosure Audit Trail',
    description:
      'Every disclosure of personal data — whether to processors, controllers, regulators, or individuals — must be captured in an immutable audit trail. P6.7 requires demonstrable evidence that disclosures were authorised, necessary, and proportionate. Code lacking audit-trail generation for disclosure events is non-compliant.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'semgrep',
      value: [
        'rules:',
        '  - id: p6-017-disclosure-audit-trail',
        '    patterns:',
        '      - pattern: |',
        '          $FUNC($DATA, ...)',
        '      - metavariable-regex:',
        '          metavariable: $FUNC',
        '          regex: (?i)(disclose|shareData|share_data|sendToThirdParty|send_to_third_party|exportData|export_data|transmitPersonalData|transmit_personal_data)',
        '      - pattern-not: |',
        '          auditLog(...)',
        '      - pattern-not: |',
        '          disclosureAudit(...)',
        '      - pattern-not: |',
        '          recordDisclosure(...)',
        '    message: Disclosure function called without an audit-trail entry',
        '    languages: [typescript, javascript, python, java, go]',
        '    severity: WARNING',
      ].join('\n'),
      explanation:
        'Uses Semgrep to find disclosure function calls that are not paired with an audit-log call, ensuring every data disclosure event generates an immutable record.',
    },
    remediation:
      'Decorate or wrap every disclosure function with an `auditDisclosure` middleware that records: actor identity, timestamp, data categories disclosed, recipient identity, legal basis, and a unique disclosure ID. Write records to an append-only audit log. Expose audit records via the compliance API for regulatory inspection.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p6-018',
    criteria: 'P6.1',
    category: 'privacy',
    title: 'No Third-Party Sub-Processor Notification',
    description:
      'When a data processor engages a sub-processor, controllers must be notified and given the opportunity to object. Failure to implement sub-processor notification violates P6.1 and undermines the accountability chain. Code that configures or onboards sub-processors without notification logic is non-compliant.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source', 'config'],
    pattern: {
      type: 'regex',
      value:
        '(?:subProcessor|sub_processor|subprocessor|vendorOnboard|vendor_onboard|addProcessor|add_processor|registerProcessor|register_processor)(?:(?!notify|notification|notifyController|notify_controller|controllerNotification|controller_notification|sendNotice|send_notice).){0,500}',
      flags: 'is',
      explanation:
        'Detects sub-processor registration or onboarding functions that do not call a controller-notification function, indicating controllers are not informed of new sub-processors as required by data processing agreements.',
    },
    remediation:
      'Implement a `SubProcessorNotificationService` that is called whenever a new sub-processor is added. It must: retrieve all active controller contacts from the DPA registry, compose a notice detailing the sub-processor name, country, services, and data categories, dispatch the notice with a 30-day objection window, and log controller acknowledgements. Block sub-processor activation until the objection window closes without a valid objection.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
];
