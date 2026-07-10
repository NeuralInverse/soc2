/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const p8Rules: ISoc2Rule[] = [
  {
    id: 'p8-001',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'Missing Privacy Incident Detection',
    description:
      'The codebase does not implement any mechanism to detect privacy incidents such as unauthorised access to personal data, unexpected bulk data exports, or anomalous PII queries. SOC2 P8.1 requires entities to monitor for privacy incidents and take corrective action. Without automated incident detection, privacy breaches may go unnoticed until significant harm has occurred.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'privacyIncident|privacy_incident|detectPrivacyBreach|privacyBreachDetect|piiAccessAnomaly|pii_access_anomaly|privacyAlertDetect|detectDataBreach|anomalyDetect.*pii|pii.*anomalyDetect',
      flags: 'i',
      explanation:
        'Scans for the presence of privacy incident detection functions, anomaly detection hooks tied to PII access, or data-breach detection integrations. Source files that handle personal data (user records, payment info, health data) but contain none of these detection patterns are flagged.',
    },
    remediation:
      'Implement automated privacy incident detection by monitoring for anomalous access patterns to personal data stores, bulk PII exports, and failed authorisation attempts on privacy-sensitive endpoints. Integrate with a SIEM or security monitoring platform and define alert thresholds for volumetric and behavioural anomalies. Create a dedicated PrivacyIncidentDetector service or middleware that emits events to your incident response pipeline whenever thresholds are crossed.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p8-002',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'No Privacy Violation Alerting',
    description:
      'The application does not configure or trigger alerts when privacy violations are detected, such as unauthorised disclosure of personal information, consent bypass, or unexpected PII exposure in responses. SOC2 P8.1 requires timely notification and response to privacy incidents. Absence of alerting means violations may be discovered only retrospectively, too late to mitigate harm.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'privacyAlert|privacy_alert|sendPrivacyAlert|notifyPrivacyViolation|privacyViolationAlert|alertOnPiiExposure|pii_alert|piiExposureAlert|privacyBreachAlert|notifyDpo|notify_dpo',
      flags: 'i',
      explanation:
        'Looks for alert-emission functions, notification calls directed at privacy officers or DPO, or alerting configuration tied to privacy events. Projects that process personal data but contain no privacy-specific alerting hooks, webhook configurations, or notification calls for privacy violations are flagged.',
    },
    remediation:
      'Configure real-time alerts for privacy violations by integrating your incident detection layer with an alerting system (PagerDuty, OpsGenie, email/SMS gateway). Define alert severity tiers: critical for data breaches or unauthorised disclosure, high for consent bypass events, medium for unexpected PII in logs. Ensure alerts route to the Data Protection Officer (DPO) and the privacy engineering team. Document response SLAs for each tier.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p8-003',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'Missing Privacy Audit Logging',
    description:
      'The application does not emit structured audit log entries for privacy-relevant operations such as access to personal data, consent changes, data deletion requests, or data exports. SOC2 P8.1 requires that privacy program effectiveness be monitored, which necessitates detailed audit trails of all privacy-relevant events. Without audit logs, demonstrating compliance and investigating incidents is not feasible.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        'auditLog(?:Privacy|Pii|PersonalData|Consent|DataAccess)|privacy_audit_log|logPrivacyEvent|emitPrivacyAudit|privacyAuditTrail|piiAuditLog|audit(?:Pii|Privacy)|recordPrivacyEvent|logDataAccess.*privacy|privacyEventLogger',
      flags: 'i',
      explanation:
        'Identifies structured privacy audit log calls, privacy event emitters, and audit trail recording functions. Files containing personal-data access or mutation operations (CRUD on user profiles, consent records, or PII fields) that do not also invoke privacy audit log functions are flagged.',
    },
    remediation:
      'Introduce a dedicated privacy audit logging service that records structured events for every privacy-relevant operation. Each event should include: event type, actor identity, affected data subject identifier (pseudonymised), data category, timestamp, and outcome. Route these logs to an immutable, tamper-evident log store separate from application logs. Retain privacy audit logs for a minimum of three years to support SOC2 evidence requirements.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p8-004',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'No Privacy Impact Assessment (PIA) Triggers',
    description:
      'The CI/CD pipeline, pull request templates, or configuration files do not include hooks or checks that trigger a Privacy Impact Assessment (PIA) when changes involve personal data processing. SOC2 P8.1 and NIST SP 800-53 require that privacy risk be assessed when introducing or modifying data-processing activities. Absence of PIA triggers means high-risk changes to privacy-sensitive code can be deployed without formal risk evaluation.',
    severity: 'high',
    languages: ['any'],
    targets: ['cicd', 'config'],
    pattern: {
      type: 'absence',
      value:
        'privacy.?impact.?assessment|pia.?required|pia.?trigger|run.?pia|privacy.?review.?required|data.?protection.?impact|dpia|DPIA|privacy.?gate|requiresPIA|piaCheck',
      flags: 'i',
      explanation:
        'Scans CI/CD pipeline definitions (GitHub Actions, GitLab CI, Jenkins), pull request templates, and configuration manifests for PIA trigger conditions or privacy review gates. Projects with no such triggers in any pipeline or template file are flagged.',
    },
    remediation:
      'Add a PIA trigger to your CI/CD pipeline and pull request template. In GitHub Actions, add a job that checks for file path patterns associated with personal data processing (models, migrations, analytics) and posts a mandatory PIA checklist comment on the PR. Add a CODEOWNERS rule requiring DPO sign-off on changes to privacy-sensitive paths. Store completed PIA records in a dedicated compliance repository linked from the PR.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p8-005',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'Missing DPA/DPO Contact Configuration',
    description:
      'The application configuration, privacy policy, or API specification does not define a Data Protection Authority (DPA) contact or a Data Protection Officer (DPO) contact. SOC2 P8.1 requires that individuals be able to contact the entity to address privacy concerns and complaints. Regulators and affected individuals must have a clear, discoverable contact point for privacy matters.',
    severity: 'medium',
    languages: ['any'],
    targets: ['config', 'source'],
    pattern: {
      type: 'absence',
      value:
        'dpo(?:Email|Contact|Address)?|dpa(?:Email|Contact|Address)?|data_protection_officer|dataProtectionOfficer|privacy(?:Contact|Officer|Email)|privacyOfficer|dpo_email|dpo_contact|privacyContactEmail|gdpr_contact',
      flags: 'i',
      explanation:
        'Searches configuration files, environment variable declarations, API specification info blocks, and privacy policy source files for DPO or DPA contact information. Projects lacking any discoverable DPO email, contact form reference, or DPA registration number in configuration or source are flagged.',
    },
    remediation:
      'Define DPO contact details in a central configuration file (e.g., privacy.config.ts or privacy.yaml) and expose them in your privacy policy, API specification info block, and privacy settings UI. At a minimum, provide a dedicated privacy contact email address (e.g., privacy@example.com) and, where required by regulation, the name and contact details of the appointed DPO. Register with the relevant DPA and include the registration reference in configuration.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p8-006',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'No Privacy Compliance Dashboard',
    description:
      'The application or its operations tooling does not implement a privacy compliance dashboard providing visibility into consent rates, data subject request volumes, PII processing activity, and privacy incident status. SOC2 P8.1 requires ongoing monitoring of the privacy program. Without a dashboard, privacy officers and auditors lack the real-time visibility needed to manage and demonstrate compliance.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'privacyDashboard|privacy_dashboard|complianceDashboard|privacyMetricsDashboard|privacyOverview|privacyStatus|dsrDashboard|dsr_dashboard|consentDashboard|privacyReportingDashboard|privacyMonitorDashboard',
      flags: 'i',
      explanation:
        'Looks for dashboard component names, route definitions, or reporting module references specifically dedicated to privacy compliance monitoring. Projects that expose admin dashboards or reporting interfaces but contain no privacy-specific dashboard module or route are flagged.',
    },
    remediation:
      'Build or integrate a privacy compliance dashboard that surfaces: current consent rates by purpose, open and closed data subject requests (DSRs) by type and SLA status, PII processing activity summaries, active privacy incidents and their resolution status, and upcoming data retention expiry batches. Restrict access to the dashboard to authorised privacy and compliance personnel. Export dashboard snapshots as part of periodic privacy program reporting.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p8-007',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'Missing Privacy Training Tracking',
    description:
      'The codebase or configuration does not include any mechanism to track completion of mandatory privacy training for employees and contractors who handle personal data. SOC2 P8.1 requires entities to enforce privacy obligations through training and awareness programs. Without tracking, the entity cannot demonstrate that personnel handling personal data have received required training.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'any'],
    targets: ['source', 'config'],
    pattern: {
      type: 'regex',
      value:
        'privacyTraining|privacy_training|trainingCompletion.*privacy|privacy.*trainingCompletion|gdprTraining|gdpr_training|privacyAwareness|privacy_awareness|trainingRecord.*privacy|privacyCertification|completedPrivacyTraining|privacyTrainingStatus',
      flags: 'i',
      explanation:
        'Detects references to privacy training tracking systems, training completion record schemas, or training status fields in HR and compliance modules. Projects that manage user or employee records but contain no privacy training tracking logic, schema fields, or integrations with an LMS are flagged.',
    },
    remediation:
      'Integrate privacy training tracking into your HR or compliance management system. Record training completion events including employee identifier, training module name, completion date, score (if applicable), and expiry date in a dedicated table or service. Trigger reminders for renewals before expiry. Expose a compliance API endpoint that returns training completion status for use in access control decisions (e.g., deny access to sensitive data interfaces for users with expired training records).',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p8-008',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'No Privacy Policy Enforcement Mechanism',
    description:
      'The application does not implement technical controls that enforce privacy policy terms at runtime, such as blocking operations that exceed declared retention periods, preventing data sharing beyond consented purposes, or rejecting API requests when consent has been withdrawn. SOC2 P8.1 requires that the entity take corrective action to address privacy deficiencies and enforce its privacy commitments through both procedural and technical controls.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'semgrep',
      value: `rules:
  - id: p8-008-no-privacy-policy-enforcement
    patterns:
      - pattern-either:
          - pattern: |
              async function $FUNC(...) {
                ...
                await $DB.$METHOD($TABLE, ...);
                ...
              }
          - pattern: |
              function $FUNC(...) {
                ...
                $DB.$METHOD($TABLE, ...);
                ...
              }
      - pattern-not: |
          enforcePrivacyPolicy(...)
      - pattern-not: |
          checkPrivacyConsent(...)
      - pattern-not: |
          validatePrivacyPolicy(...)
      - pattern-not: |
          assertConsentValid(...)
    message: >
      Database operation in function without privacy policy enforcement or consent
      validation guard. Wrap data access operations with privacy enforcement middleware.
    languages: [typescript, javascript]
    severity: WARNING`,
      explanation:
        'Identifies asynchronous or synchronous database access functions that mutate or query personal data tables without invoking a privacy policy enforcement guard, consent validation function, or purpose-limitation check. Functions whose names suggest personal data operations but which contain no privacy enforcement calls are flagged.',
    },
    remediation:
      "Introduce a privacy policy enforcement layer as middleware or a decorator that intercepts data access operations and validates them against the current privacy policy version, the user's active consent record, and the declared retention schedule. Reject or quarantine operations that fall outside consented purposes. Log enforcement decisions to the privacy audit log. Consider using a Policy Decision Point (PDP) pattern to centralise enforcement logic.",
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p8-009',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'Missing Privacy-by-Design Checklist',
    description:
      'Pull request templates, issue templates, or CI/CD pipeline configurations do not include a Privacy-by-Design (PbD) checklist that developers must complete when introducing features that collect or process personal data. SOC2 P8.1 requires systematic monitoring and enforcement of privacy practices; PbD checklists are a key preventive control ensuring privacy requirements are considered before code is merged.',
    severity: 'medium',
    languages: ['any'],
    targets: ['cicd', 'config'],
    pattern: {
      type: 'absence',
      value:
        'privacy.?by.?design|pbd.?checklist|privacy.?checklist|privacy-checklist|privacyByDesign|privacy_by_design|pii.?checklist|data.?minimisation.?checklist|privacy.?review.?checklist|privacy.?design.?review',
      flags: 'i',
      explanation:
        'Scans pull request template files (.github/PULL_REQUEST_TEMPLATE.md, .gitlab/merge_request_templates/), issue templates, and CI gate configurations for Privacy-by-Design checklist items or privacy review prompts. Repositories that lack any such template content are flagged.',
    },
    remediation:
      'Add a Privacy-by-Design checklist section to your pull request template. The checklist should prompt developers to confirm: data minimisation has been applied, consent is obtained before collection, a PIA has been conducted if required, personal data is encrypted at rest and in transit, retention periods are defined, data subject rights mechanisms are implemented, and the privacy audit log is instrumented. Require the checklist to be completed before PR review can begin by enforcing it via a required PR check.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p8-010',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'No Automated PII Scanning in Logs',
    description:
      'The logging pipeline does not include automated PII detection and redaction before log entries are written to storage. SOC2 P8.1 requires that the entity monitor for and remediate privacy deficiencies. Logging PII in plaintext is a common source of unintended disclosure and creates unnecessary data retention obligations. Automated scanning and redaction is the primary control for preventing PII from entering log stores.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby'],
    targets: ['source', 'config'],
    pattern: {
      type: 'regex',
      value:
        'piiScan|pii_scan|scanForPii|redactPii|pii_redact|piiRedact|maskPii|pii_mask|sanitizePii|pii_sanitize|piiDetect|detectPii|piiFilter|filterPii|scrubPii|pii_scrub|logSanitizer.*pii|pii.*logSanitizer',
      flags: 'i',
      explanation:
        'Identifies PII scanning, redaction, masking, or sanitisation functions integrated into the logging pipeline. Projects that configure structured loggers (Winston, Pino, Log4j, zap) or write to log aggregation services (Datadog, Splunk, CloudWatch) without any PII scanning middleware or output transform are flagged.',
    },
    remediation:
      'Integrate a PII scanning and redaction layer into your logging middleware. Before any log entry is written, run the serialised log object through a PII scanner that detects and redacts common PII patterns: email addresses, phone numbers, social security numbers, credit card numbers, passport numbers, IP addresses (where applicable), and names. Use a library such as scrubadub (Python), log-scrubber (Node.js), or a custom regex-based sanitiser. Apply redaction at the logger transport layer so that no downstream log sink ever receives raw PII.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p8-011',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'Missing Privacy Regression Testing',
    description:
      'The test suite does not include privacy regression tests that verify privacy controls remain effective after code changes. SOC2 P8.1 requires continuous monitoring of privacy program effectiveness. Without automated privacy regression tests, refactoring or dependency updates may silently break consent enforcement, data minimisation, or PII redaction controls without detection.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'cicd'],
    pattern: {
      type: 'absence',
      value:
        'privacyTest|privacy_test|testPrivacy|privacySpec|privacy\\.spec|privacy\\.test|privacyRegression|privacy_regression|testPiiRedaction|testConsentEnforcement|privacyComplianceTest|privacyControlTest|piiScanTest|testPrivacyAudit',
      flags: 'i',
      explanation:
        'Searches the test directory and CI pipeline configuration for privacy-specific test files, test suites, and regression test jobs. Projects that have test suites but lack any test files whose names or describe blocks indicate coverage of privacy controls are flagged.',
    },
    remediation:
      'Create a dedicated privacy regression test suite covering: consent enforcement (verify data access is blocked when consent is absent), PII redaction in logs (verify no PII appears in log output after an operation), data subject rights fulfilment (verify deletion and export operations complete correctly), retention policy enforcement (verify expired data is purged on schedule), and privacy incident detection (verify alerts fire under simulated breach conditions). Run this suite on every pull request and as part of the nightly regression pipeline. Gate deployment on passing privacy regression tests.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'p8-012',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'No Privacy Metrics Collection',
    description:
      'The application does not collect or expose quantitative privacy metrics such as consent opt-in rates, data subject request (DSR) volumes and SLA adherence, PII incident counts, or data retention compliance rates. SOC2 P8.1 requires that the privacy program be monitored and its effectiveness measured. Without metrics, the privacy program cannot be evaluated, improved, or evidenced during an audit.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'config'],
    pattern: {
      type: 'regex',
      value:
        'privacyMetric|privacy_metric|recordPrivacyMetric|incrementPrivacyStat|privacyKpi|privacy_kpi|dsrMetric|dsr_metric|consentMetric|consent_metric|piiIncidentCount|privacyEventCount|privacyMeasure|collectPrivacyStat|privacyTelemetry',
      flags: 'i',
      explanation:
        'Identifies metric recording calls, counter increments, and telemetry emissions specifically tied to privacy-relevant events. Projects that emit application metrics (via Prometheus, StatsD, OpenTelemetry, or Datadog) but contain no privacy-specific metric collection calls are flagged.',
    },
    remediation:
      'Define and instrument a privacy metrics catalogue. Emit the following metrics at a minimum: consent_opt_in_total (counter), consent_opt_out_total (counter), dsr_received_total (counter, labelled by request type), dsr_fulfilled_duration_seconds (histogram), pii_incident_total (counter, labelled by severity), pii_log_redaction_total (counter), data_retention_purge_total (counter). Expose these metrics to your monitoring platform and create dashboards and SLA alerting rules around them. Include metric trend reports in quarterly privacy program reviews.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p8-013',
    criteria: 'P8.1',
    category: 'privacy',
    title: 'Missing Privacy Program Documentation',
    description:
      'The repository does not contain or reference privacy program documentation such as a Records of Processing Activities (RoPA), data flow diagrams, privacy control inventory, or vendor data processing agreements (DPAs). SOC2 P8.1 requires that the privacy program be documented and that documentation be maintained current. Auditors require this documentation as primary evidence of a functioning privacy program.',
    severity: 'medium',
    languages: ['any'],
    targets: ['config', 'source'],
    pattern: {
      type: 'absence',
      value:
        'ropa|records.?of.?processing|data.?flow.?diagram|dfd.*privacy|privacy.*dfd|privacy.?control.?inventory|data.?processing.?agreement|dpa.*vendor|vendor.*dpa|privacy.?program.*doc|privacyProgramDoc|privacy.?runbook|privacy.?handbook|privacyPolicy.*internal|internalPrivacyPolicy',
      flags: 'i',
      explanation:
        'Searches for documentation references, file path constants, or configuration pointers that lead to privacy program artefacts such as RoPA, data flow diagrams, DPA templates, and control inventories. Projects lacking any such references in their configuration, README, or source are flagged.',
    },
    remediation:
      'Establish and maintain a privacy program documentation set including: a Records of Processing Activities (RoPA) enumerating each processing activity, its legal basis, data categories, retention period, and recipients; data flow diagrams for all personal data flows; a privacy control inventory mapping controls to SOC2 P8.1 and other applicable criteria; executed DPAs with all data processors; and a privacy incident response runbook. Store this documentation in a version-controlled compliance repository and reference it from your project README and configuration. Review and update documentation at least annually and after material changes to data-processing activities.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
      'https://www.nist.gov/cyberframework',
    ],
  },
];
