/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const c1ClassificationRules: ISoc2Rule[] = [
  {
    id: 'c1-class-001',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Data Classification Labels in Configuration',
    description:
      'Configuration files lack explicit data classification labels. Without classification metadata, automated controls cannot enforce appropriate handling of sensitive data assets.',
    severity: 'high',
    languages: ['any'],
    targets: ['config'],
    pattern: {
      type: 'absence',
      value: '(classification|data[_-]class|sensitivity[_-]level|data[_-]sensitivity)',
      flags: 'i',
      explanation:
        'Detects configuration files that do not contain any data classification or sensitivity level declarations.',
    },
    remediation:
      'Add a top-level `classification` key to all configuration files. Use values such as `public`, `internal`, `confidential`, or `restricted` consistent with your data classification policy. Example: `classification: confidential`.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'c1-class-002',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No PII Data Classification Annotation',
    description:
      'Fields or columns containing Personally Identifiable Information (PII) are not annotated with a PII classification marker. This omission prevents downstream enforcement of privacy controls and data-subject rights obligations.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'csharp'],
    targets: ['source', 'schema'],
    pattern: {
      type: 'regex',
      value:
        '(email|phone|ssn|social[_\\s]?security|passport|date[_\\s]?of[_\\s]?birth|dob|address|first[_\\s]?name|last[_\\s]?name|full[_\\s]?name)[^\\n]*(?!.*@pii|.*PII|.*pii|.*personally[_\\s]identifiable)',
      flags: 'i',
      explanation:
        'Matches field or variable names that suggest PII content but lack a @pii annotation or PII classification comment on the same line.',
    },
    remediation:
      'Annotate all PII fields with a recognised classification decorator or comment. In TypeScript/JavaScript use JSDoc `@pii`, in Python use a `# pii: true` inline comment, and in schema files add a `classification: pii` property. Integrate a linting rule that enforces this annotation at build time.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },
  {
    id: 'c1-class-003',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing PHI Classification Marker',
    description:
      'Protected Health Information (PHI) fields are not tagged with a PHI classification label. Unclassified PHI cannot be automatically subjected to HIPAA-mandated safeguards, audit logging, or access restrictions.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'csharp', 'ruby'],
    targets: ['source', 'schema'],
    pattern: {
      type: 'regex',
      value:
        '(diagnosis|icd[_\\-]?\\d|medication|prescription|health[_\\s]?record|medical[_\\s]?history|lab[_\\s]?result|vital[_\\s]?sign|patient[_\\s]?id|mrn|npi)[^\\n]*(?!.*@phi|.*PHI|.*phi|.*protected[_\\s]health)',
      flags: 'i',
      explanation:
        'Matches field names indicative of PHI content but lacking a @phi annotation or PHI classification comment.',
    },
    remediation:
      'Tag every PHI field with `@phi` in code comments or decorators and add `classification: phi` in schema definitions. Ensure that PHI classification triggers automatic encryption, access control, and audit logging via policy enforcement hooks.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'c1-class-004',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No PCI Data Marking',
    description:
      'Fields or variables holding Payment Card Industry (PCI) data such as card numbers, CVVs, or expiry dates lack explicit PCI classification markers, preventing automatic application of PCI-DSS controls.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby', 'php'],
    targets: ['source', 'schema'],
    pattern: {
      type: 'regex',
      value:
        '(card[_\\s]?number|pan|primary[_\\s]?account[_\\s]?number|cvv|cvc|cvv2|expir|card[_\\s]?holder|cardholder)[^\\n]*(?!.*@pci|.*PCI|.*pci|.*payment[_\\s]card)',
      flags: 'i',
      explanation:
        'Matches field names that indicate payment card data without a corresponding PCI classification annotation on the same line.',
    },
    remediation:
      'Mark all PCI-scoped fields with `@pci` annotations or `classification: pci` in schema definitions. Enforce tokenisation of card numbers at the point of entry and ensure that any field classified as PCI triggers mandatory encryption and audit controls.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },
  {
    id: 'c1-class-005',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Sensitive Data Inventory',
    description:
      'The project lacks a data inventory file or manifest that catalogues sensitive data assets and their classifications. Without a data inventory, it is impossible to consistently apply classification-based controls across the organisation.',
    severity: 'high',
    languages: ['any'],
    targets: ['config', 'iac'],
    pattern: {
      type: 'absence',
      value:
        '(data[_\\-]inventory|data[_\\-]catalog|data[_\\-]catalogue|sensitive[_\\-]data[_\\-]register|data[_\\-]register)',
      flags: 'i',
      explanation:
        'Detects the absence of any data inventory or data catalogue reference in configuration and infrastructure-as-code files.',
    },
    remediation:
      'Create a `data-inventory.yaml` or equivalent file at the repository root that lists all data assets, their classification levels, owners, retention periods, and applicable controls. Reference this inventory in your IaC and CI/CD pipelines to enforce classification-driven policies automatically.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'c1-class-006',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No Classification Policy Enforcement in CI/CD',
    description:
      'CI/CD pipeline definitions do not include a classification policy enforcement step. Without an automated gate, code that handles sensitive data can be merged and deployed without confirming it meets classification requirements.',
    severity: 'high',
    languages: ['any'],
    targets: ['cicd'],
    pattern: {
      type: 'absence',
      value:
        '(classification[_\\-]check|data[_\\-]class|sensitivity[_\\-]scan|dlp[_\\-]scan|policy[_\\-]enforce)',
      flags: 'i',
      explanation:
        'Detects CI/CD pipeline files that contain no reference to classification checking, DLP scanning, or policy enforcement steps.',
    },
    remediation:
      'Add a dedicated classification-policy enforcement job to every pipeline. Use a DLP scanner (e.g., Nightfall, Macie, or an open-source equivalent) as a required check before merging or deploying. Fail the build when unclassified sensitive data patterns are detected.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://www.cisecurity.org/cis-benchmarks',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },
  {
    id: 'c1-class-007',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Data Classification in Database Schemas',
    description:
      'Database migration files and schema definitions do not include column-level classification metadata via comments or extended attributes. Unclassified schema columns cannot be governed by automated data lifecycle and access control policies.',
    severity: 'high',
    languages: ['any'],
    targets: ['migration', 'schema'],
    pattern: {
      type: 'absence',
      value: '(classification|sensitivity|data[_\\-]class|pii|phi|pci|confidential|restricted)',
      flags: 'i',
      explanation:
        'Detects migration and schema files that contain no classification, sensitivity, or data-category annotations on column or field definitions.',
    },
    remediation:
      'Add COMMENT or metadata attributes to every sensitive column. For SQL use `COMMENT ON COLUMN table.column IS \'classification:confidential\'`. For ORM schemas, add a `classification` key to column metadata. Automate schema-lint checks that reject PRs adding sensitive columns without classification comments.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'c1-class-008',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No Field-Level Sensitivity Annotations in Source Models',
    description:
      'Data model classes or structs define sensitive fields without field-level sensitivity decorators or annotations. This prevents runtime frameworks from applying field-specific masking, access control, or audit logging.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'csharp', 'go'],
    targets: ['source'],
    pattern: {
      type: 'semgrep',
      value: [
        'rules:',
        '  - id: c1-class-008-no-field-sensitivity',
        '    patterns:',
        '      - pattern: |',
        '          class $CLASS {',
        '            ...',
        '            $FIELD: $TYPE',
        '            ...',
        '          }',
        '      - pattern-not: |',
        '          class $CLASS {',
        '            ...',
        '            @Sensitive(...)',
        '            $FIELD: $TYPE',
        '            ...',
        '          }',
        '    message: Field $FIELD in $CLASS lacks a sensitivity annotation.',
        '    languages: [typescript, javascript]',
        '    severity: WARNING',
      ].join('\n'),
      explanation:
        'Detects class fields that are not preceded by a @Sensitive decorator or a sensitivity inline comment.',
    },
    remediation:
      'Introduce a `@Sensitive` decorator (or equivalent for your language) for all model fields that may carry confidential data. Configure your ORM or serialisation layer to redact or mask fields marked `@Sensitive` in logs and API responses by default.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },
  {
    id: 'c1-class-009',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Classification-Based Access Controls',
    description:
      'Access control definitions do not reference data classification levels as conditions for granting permissions. Without classification-aware access controls, all users may access highly sensitive data regardless of need-to-know.',
    severity: 'critical',
    languages: ['any'],
    targets: ['config', 'iac', 'source'],
    pattern: {
      type: 'absence',
      value:
        '(classification[_\\-]based|sensitivity[_\\-]based|data[_\\-]class.*allow|clearance[_\\-]level|need[_\\-]to[_\\-]know)',
      flags: 'i',
      explanation:
        'Detects access control configurations or policy files that do not include any classification-based access condition.',
    },
    remediation:
      'Extend your IAM and ABAC policies to include `classification` as an attribute condition. For example, add a policy condition such as `data.classification == "confidential" && principal.clearance >= "confidential"`. Verify that every restricted or confidential resource has a corresponding classification-based policy attached.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'c1-class-010',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No Data Flow Documentation',
    description:
      'The codebase or infrastructure repository contains no data flow diagram, data flow manifest, or DFD reference. Absence of documented data flows prevents classification teams from identifying where sensitive data travels and applying appropriate controls at each boundary.',
    severity: 'medium',
    languages: ['any'],
    targets: ['config', 'iac'],
    pattern: {
      type: 'absence',
      value: '(data[_\\-]flow|dfd|dataflow|data[_\\-]lineage|lineage|data[_\\-]map)',
      flags: 'i',
      explanation:
        'Detects configuration and IaC repositories that contain no reference to data flow documentation, data lineage, or data mapping artefacts.',
    },
    remediation:
      'Produce a Data Flow Diagram (DFD) for every system that processes confidential or restricted data. Store the DFD as a versioned artefact (e.g., `docs/data-flow.drawio` or `data-flow.yaml`) and reference it from your SECURITY.md. Review and update the diagram whenever data paths change.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'c1-class-011',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Sensitive Field Encryption',
    description:
      'Sensitive fields identified through naming conventions (e.g., ssn, password, secret) are stored or transmitted without explicit encryption calls. Storing sensitive data in plaintext violates confidentiality requirements and data classification policies.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby', 'php'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(ssn|social_security|password_hash|secret_key|private_key|api_secret)\\s*[=:]\\s*["\'][^"\']+["\'](?!.*encrypt|.*cipher|.*hash)',
      flags: 'i',
      explanation:
        'Matches assignments of sensitive field values to plaintext string literals without an accompanying encryption, cipher, or hash operation on the same line.',
    },
    remediation:
      'Never store sensitive fields as plaintext literals. Use an approved encryption library (e.g., `crypto.createCipheriv` in Node.js, `cryptography.fernet` in Python) to encrypt values before persistence. For passwords, use an adaptive hashing algorithm such as bcrypt or Argon2. Enforce this via static analysis rules in your CI pipeline.',
    references: [
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
    ],
  },
  {
    id: 'c1-class-012',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No Tokenisation for PCI Data',
    description:
      'Payment card handling code stores or logs raw card numbers (PANs) without tokenisation. PCI-DSS requires that PANs be replaced with non-sensitive tokens before any storage or transmission outside of the card data environment.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby', 'php'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(card[_\\s]?number|pan|primary[_\\s]?account[_\\s]?number)\\s*[=:]\\s*[^\\n]+(?!.*token|.*tokeniz|.*tokenise|.*vault)',
      flags: 'i',
      explanation:
        'Matches card number assignments that do not reference a tokenisation or vaulting call, suggesting PANs may be stored or transmitted in the clear.',
    },
    remediation:
      'Integrate a PCI-compliant tokenisation service (e.g., Stripe, Braintree vault, or an internal token server) at the point where card data enters your system. Replace the PAN immediately with a token and discard the raw value. Never log, store, or pass the raw PAN beyond the initial tokenisation boundary.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },
  {
    id: 'c1-class-013',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Data Masking in Log Statements',
    description:
      'Log statements output sensitive data fields (e.g., email, password, card number) without masking or redaction. Application logs are frequently stored in less-secure log aggregators and must never contain unmasked confidential data.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby', 'php'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(console\\.log|logger\\.info|logger\\.debug|log\\.info|log\\.debug|print|System\\.out\\.println|fmt\\.Print)\\s*\\([^)]*?(password|ssn|card[_\\s]?number|cvv|secret|api[_\\s]?key|private[_\\s]?key|email|phone)[^)]*\\)',
      flags: 'i',
      explanation:
        'Matches logging calls whose argument list contains sensitive field names, indicating that confidential data may be written to logs without masking.',
    },
    remediation:
      'Never log sensitive fields directly. Use a structured logging framework with a field-level redaction filter (e.g., Pino `redact` option, Logback `MaskingPatternLayout`, or a custom log sanitiser). Add a pre-commit hook and CI check that fails when log statements contain known sensitive field names without a masking wrapper.',
    references: [
      'https://owasp.org/www-project-top-ten/',
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },
  {
    id: 'c1-class-014',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Sensitive Data Exposed in Error Messages',
    description:
      'Error or exception handling code constructs error messages that include raw sensitive data values. Exposing confidential data in error messages risks leakage through client-facing API responses, support tickets, or monitoring dashboards.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby', 'php'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        '(throw\\s+new\\s+Error|raise\\s+Exception|new\\s+RuntimeException|fmt\\.Errorf|errors\\.New)\\s*\\([^)]*?(password|ssn|card[_\\s]?number|cvv|secret|token|api[_\\s]?key)[^)]*\\)',
      flags: 'i',
      explanation:
        'Matches error construction expressions whose message argument includes sensitive field names, suggesting raw confidential values may appear in thrown exceptions.',
    },
    remediation:
      'Construct error messages using opaque error codes or safe descriptions that do not include sensitive field values. Log the full diagnostic details (with masking) server-side only and return a sanitised, reference-code-based error to clients. Add a linting rule to your CI pipeline that flags error constructors containing sensitive field names.',
    references: [
      'https://owasp.org/www-project-top-ten/',
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },
  {
    id: 'c1-class-015',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Classification Metadata in API Documentation',
    description:
      'OpenAPI, AsyncAPI, or similar API specification files do not include data classification extensions on schemas that carry sensitive fields. Without classification metadata in the spec, API consumers and automated governance tools cannot determine how to handle responses that contain confidential data.',
    severity: 'medium',
    languages: ['any'],
    targets: ['config'],
    pattern: {
      type: 'absence',
      value:
        '(x-classification|x-sensitivity|x-data-class|x-pii|x-phi|x-pci|x-confidential|x-restricted)',
      flags: 'i',
      explanation:
        'Detects API specification files that lack any vendor-extension classification property on their schema objects.',
    },
    remediation:
      'Add `x-classification` vendor extensions to every OpenAPI schema property that may carry sensitive data. For example: `x-classification: confidential`. Integrate an API linting step (e.g., Spectral) with a custom rule that requires `x-classification` on any property whose name matches known sensitive field patterns.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },
  {
    id: 'c1-class-016',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No Data Retention Policy by Classification Level',
    description:
      'Infrastructure and configuration files define no retention policies differentiated by data classification level. Applying uniform retention to all data ignores the higher risk posed by retaining confidential or restricted data beyond its useful life.',
    severity: 'high',
    languages: ['any'],
    targets: ['config', 'iac'],
    pattern: {
      type: 'absence',
      value:
        '(retention[_\\-]policy|data[_\\-]retention|retention[_\\-]period|retention[_\\-]class|lifecycle[_\\-]rule.*class|class.*retention)',
      flags: 'i',
      explanation:
        'Detects configuration and IaC files that contain no classification-aware data retention or lifecycle policy definitions.',
    },
    remediation:
      'Define explicit retention policies for each classification tier (e.g., `public: 7 years`, `confidential: 3 years`, `restricted: 1 year`). Implement these via cloud storage lifecycle rules, database partition strategies, or a dedicated data lifecycle service. Automate deletion at the end of the retention period and log the deletion event for audit purposes.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'c1-class-017',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Cross-Border Data Transfer Controls',
    description:
      'Configuration and IaC files that provision data storage or processing resources lack cross-border transfer restrictions tied to data classification. Confidential and restricted data may be replicated to regions that do not meet regulatory requirements.',
    severity: 'high',
    languages: ['any'],
    targets: ['iac', 'config'],
    pattern: {
      type: 'absence',
      value:
        '(cross[_\\-]border|data[_\\-]residency|geo[_\\-]restriction|allowed[_\\-]region|region[_\\-]restriction|data[_\\-]sovereignty)',
      flags: 'i',
      explanation:
        'Detects IaC and configuration files that provision data resources without any data residency, cross-border transfer restriction, or geo-restriction setting.',
    },
    remediation:
      'Tag every data resource in IaC with a `data_classification` label and enforce region restrictions through policy-as-code (e.g., AWS SCPs, Azure Policy, GCP Organisation Policy). For confidential and restricted classifications, explicitly deny replication to non-approved regions. Document transfer impact assessments for any cross-border flow.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'c1-class-018',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No Classification Change Auditing',
    description:
      "The codebase and configuration contain no mechanism to audit or log changes to a data asset's classification level. Untracked classification changes create a gap in the audit trail required to demonstrate continuous compliance.",
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        '(classification[_\\-]change|reclassif|classification[_\\-]audit|audit.*classification|classification.*log)',
      flags: 'i',
      explanation:
        'Detects source and configuration files that contain no reference to classification change auditing, reclassification events, or classification audit logs.',
    },
    remediation:
      "Implement an audit event that fires whenever a data asset's classification is modified. Log the old classification, new classification, actor identity, timestamp, and justification to an immutable audit store. Expose classification change history via an administrative API and include it in periodic compliance reports.",
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
  {
    id: 'c1-class-019',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Encryption at Rest Enforcement for Classified Data',
    description:
      'Storage resource definitions in IaC or configuration do not enforce server-side encryption for resources that are tagged or expected to hold classified data. Data at rest without encryption is exposed to physical media theft and insider threats.',
    severity: 'critical',
    languages: ['any'],
    targets: ['iac', 'config'],
    pattern: {
      type: 'regex',
      value:
        '(encrypted\\s*[=:]\\s*false|encryption\\s*[=:]\\s*false|server_side_encryption\\s*[=:]\\s*false|storage_encrypted\\s*[=:]\\s*false|enable_encryption\\s*[=:]\\s*false)',
      flags: 'i',
      explanation:
        'Matches IaC resource definitions that explicitly disable encryption at rest, leaving stored data unprotected.',
    },
    remediation:
      'Set `encrypted = true` (or the equivalent) on all storage resources that hold internal, confidential, or restricted data. Use a customer-managed key (CMK) for confidential and restricted classifications and enforce this requirement through a policy-as-code check that fails deployments with encryption disabled.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'c1-class-020',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No Encryption in Transit Enforcement for Classified Data',
    description:
      'Network or service configuration allows plaintext (non-TLS) communication for endpoints that handle classified data. Transmitting confidential data over unencrypted channels exposes it to interception and man-in-the-middle attacks.',
    severity: 'critical',
    languages: ['any'],
    targets: ['iac', 'config'],
    pattern: {
      type: 'regex',
      value:
        '(tls[_\\-]?enabled\\s*[=:]\\s*false|ssl[_\\-]?enabled\\s*[=:]\\s*false|enforce[_\\-]?https\\s*[=:]\\s*false|require[_\\-]?tls\\s*[=:]\\s*false)',
      flags: 'i',
      explanation:
        'Matches configuration entries that explicitly disable TLS/SSL, indicating data may be transmitted in plaintext.',
    },
    remediation:
      'Enable TLS for all service-to-service and client-to-service communication. Set a minimum TLS version of 1.2 and prefer 1.3 for confidential and restricted data channels. Enforce HTTPS-only redirects and add HSTS headers. Use policy-as-code to block deployments that permit plaintext protocols on classified data paths.',
    references: [
      'https://owasp.org/www-project-top-ten/',
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },
  {
    id: 'c1-class-021',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'Missing Key Management Configuration for Classified Data',
    description:
      'IaC and configuration files that define encryption resources for classified data do not specify a key management service (KMS) configuration or customer-managed key (CMK). Without explicit key management, the platform default key may be shared across tenants and classification tiers, undermining cryptographic separation.',
    severity: 'high',
    languages: ['any'],
    targets: ['iac', 'config'],
    pattern: {
      type: 'absence',
      value:
        '(kms[_\\-]?key|key[_\\-]?arn|cmk|customer[_\\-]managed[_\\-]key|key[_\\-]?id|encryption[_\\-]?key|master[_\\-]?key)',
      flags: 'i',
      explanation:
        'Detects IaC and configuration files that define encrypted resources but do not reference a KMS key, CMK, or customer-managed encryption key.',
    },
    remediation:
      'Provision a dedicated KMS key for each classification tier (e.g., `kms-key-confidential`, `kms-key-restricted`). Reference the appropriate key in every encrypted resource definition using the `kms_key_id` or equivalent attribute. Enforce key rotation schedules (at least annually) and restrict key usage via IAM key policies to only authorised principals.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'c1-class-022',
    criteria: 'C1.1',
    category: 'confidentiality',
    title: 'No Classification-Based Data Deletion Mechanism',
    description:
      'The codebase and infrastructure configuration contain no implementation or reference to a classification-based secure deletion routine. Data classified as confidential or restricted must be securely and verifiably deleted when its retention period expires or a data-subject deletion request is received.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby'],
    targets: ['source', 'config', 'iac'],
    pattern: {
      type: 'absence',
      value:
        '(secure[_\\-]?delete|crypto[_\\-]?erase|data[_\\-]?purge|right[_\\-]?to[_\\-]?erasure|deletion[_\\-]?policy|purge[_\\-]?on[_\\-]?expiry|classification.*delete|delete.*classification)',
      flags: 'i',
      explanation:
        'Detects source, configuration, and IaC files that contain no reference to secure deletion, cryptographic erasure, data purge routines, or right-to-erasure workflows tied to data classification.',
    },
    remediation:
      'Implement a `SecureDeletionService` that accepts a classification level and data asset identifier. For `confidential` and `restricted` classifications, perform cryptographic erasure (delete the CMK) in addition to logical deletion. Log every deletion event with the classification level, asset ID, actor, and timestamp to an immutable audit store. Trigger this service automatically at retention period expiry and in response to data-subject erasure requests.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
];
