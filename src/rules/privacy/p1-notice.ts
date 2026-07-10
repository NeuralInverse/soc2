/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const p1Rules: ISoc2Rule[] = [
  {
    id: 'p1-001',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'Missing Privacy Policy Link in UI',
    description:
      'Application UI components do not include a visible link or reference to the privacy policy. SOC2 P1.1 requires that entities communicate their privacy notice to individuals at or before the time personal information is collected. Absence of a privacy policy link in UI renders this requirement unmet.',
    severity: 'high',
    languages: ['typescript', 'javascript'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'privacy[-_]?policy|privacyPolicy|privacy[-_]?notice|PrivacyLink|privacy[-_]?url',
      flags: 'i',
      explanation:
        'Detects source files that render UI but contain no reference to a privacy policy link, notice component, or privacy URL constant. Files matching UI rendering patterns (JSX/TSX render methods, template literals with HTML) but lacking privacy policy references are flagged.',
    },
    remediation:
      'Add a clearly visible privacy policy link in your application footer, registration forms, and any page that collects personal information. Ensure the link is accessible and rendered consistently across all UI entry points. Example: <a href="/privacy-policy">Privacy Policy</a>.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p1-002',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'No Cookie Consent Banner Implementation',
    description:
      'The codebase does not implement a cookie consent banner or consent management mechanism. Regulations such as GDPR and ePrivacy Directive, aligned with SOC2 P1.1 notice requirements, mandate that users be informed about cookie usage and given meaningful consent choices before non-essential cookies are set.',
    severity: 'high',
    languages: ['typescript', 'javascript'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        'document\\.cookie\\s*=|setCookie\\s*\\(|cookies?\\.set\\s*\\(|js-cookie|cookie-consent|cookieConsent|CookieBanner|useCookieConsent',
      flags: 'i',
      explanation:
        'Detects cookie-setting operations (document.cookie assignment, setCookie calls, js-cookie library usage) without accompanying consent banner or consent management patterns. Flags files where cookies are set without evidence of consent handling logic.',
    },
    remediation:
      'Implement a cookie consent banner that categorises cookies (essential, analytics, marketing) and captures user consent before setting non-essential cookies. Use a consent management platform (CMP) or a library such as react-cookie-consent. Store consent decisions and honour opt-outs. Reference consent state before calling any non-essential cookie-setting code.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p1-003',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'Missing Privacy Notice at Data Collection Points',
    description:
      'Forms or components that collect personal data (name, email, phone, address) do not display an inline privacy notice at the point of collection. SOC2 P1.1 requires notice to be provided at or before the time personal information is collected, not merely in a standalone privacy policy page.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'php'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        'type=["\']email["\']|type=["\']tel["\']|name=["\'](?:firstName|lastName|fullName|phone|address|dob|dateOfBirth|ssn|nationalId)["\']|input.*personal|collectPersonalData|saveUserProfile',
      flags: 'i',
      explanation:
        'Identifies input fields and data-collection function calls that handle personal information. When these patterns appear in files that do not also contain inline privacy notice text, a privacy notice annotation, or a reference to a notice component, the rule fires.',
    },
    remediation:
      'Add a brief inline privacy notice adjacent to every data-collection form or input group. The notice should state what data is collected, why it is collected, how it will be used, and provide a link to the full privacy policy. Example: "We collect your email to send account notifications. See our <a href=\"/privacy\">Privacy Policy</a>."',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p1-004',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'No Clear Data Usage Explanation',
    description:
      'Privacy policy or notice documents in the codebase do not contain an explicit explanation of how collected personal data will be used. SOC2 P1.1 mandates that the privacy notice describe the purposes for which personal information is collected, used, retained, and disclosed.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'any'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        'how we use|purpose of collection|data usage|use your (personal |personal information|data)|we collect.*in order to|collected for the purpose',
      flags: 'i',
      explanation:
        'Scans privacy policy text files, privacy notice components, and configuration-driven notice strings for explicit data usage language. Files identified as privacy notices (by filename or export name) that omit purpose-of-collection explanations are flagged.',
    },
    remediation:
      'Amend the privacy notice to include a dedicated "How We Use Your Information" section. Enumerate each category of data collected alongside the specific purpose(s) for its collection. Avoid vague language such as "to improve services" — be specific about operational, analytical, and marketing uses.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p1-005',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'Missing Notice of Third-Party Data Sharing',
    description:
      'Code that transmits personal data to third-party services, SDKs, or APIs does not have corresponding privacy-notice disclosures about third-party sharing. SOC2 P1.1 requires entities to disclose categories of third parties with whom personal information is shared and the purposes of sharing.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source'],
    pattern: {
      type: 'semgrep',
      value: `rules:
  - id: p1-005-third-party-sharing-no-notice
    patterns:
      - pattern-either:
          - pattern: fetch($URL, ...)
          - pattern: axios.$METHOD($URL, ...)
          - pattern: http.post($URL, ...)
          - pattern: requests.post($URL, ...)
      - pattern-not-inside: |
          // third-party disclosure: ...
      - pattern-not-inside: |
          /* third-party: ... */
    message: Personal data sent to third-party endpoint without adjacent disclosure comment
    languages: [javascript, typescript, python]
    severity: WARNING`,
      explanation:
        'Detects outbound HTTP calls to external endpoints that transmit user or personal data without an inline code comment indicating third-party disclosure awareness. Calls inside functions whose names or surrounding context suggest analytics, advertising, or data enrichment are prioritised.',
    },
    remediation:
      'Update the privacy notice to list all third-party recipients of personal data, the categories of data shared, and the purposes. In code, annotate third-party data-sharing calls with a disclosure comment referencing the privacy notice section. Implement a vendor management process to review new third-party integrations for privacy impact before deployment.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p1-006',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'No Notification Mechanism for Material Privacy Policy Changes',
    description:
      "The application does not implement any mechanism to notify existing users of material changes to the privacy policy. SOC2 P1.1 requires that individuals be notified of changes to the entity's privacy practices in a timely manner.",
    severity: 'medium',
    languages: ['typescript', 'javascript'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'privacyPolicyVersion|privacy_policy_version|policyVersion|notifyPrivacyChange|sendPrivacyUpdateEmail|privacyChangeNotif|lastPrivacyAccepted',
      flags: 'i',
      explanation:
        'Looks for version-tracking fields and notification-trigger functions related to privacy policy changes. Projects lacking any version comparison logic, email notification triggers, or forced re-acceptance flows for privacy policy updates are flagged.',
    },
    remediation:
      'Implement a privacy policy versioning system. Store the version the user last accepted in the user profile. On login or first visit after a policy update, display a modal or banner informing the user of material changes and require re-acceptance. Additionally, send an email notification to affected users describing the changes before they take effect.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
  {
    id: 'p1-007',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'Missing Multilingual Privacy Support Hooks',
    description:
      'The application serves users across multiple locales but does not implement internationalisation hooks for the privacy notice. SOC2 P1.1 requires that privacy notices be presented in a language understandable by the individual. Absence of i18n support for privacy content may prevent non-English speakers from comprehending their privacy rights.',
    severity: 'medium',
    languages: ['typescript', 'javascript'],
    targets: ['source', 'config'],
    pattern: {
      type: 'regex',
      value:
        'i18n|intl|useTranslation|t\\(["\']privacy|locale.*privacy|privacy.*locale|formatMessage.*privacy|privacy_notice_[a-z]{2}|translations?\\.privacy',
      flags: 'i',
      explanation:
        'Scans for i18n library usage (react-i18next, next-intl, vue-i18n, FormatJS) applied specifically to privacy notice content. Files containing privacy notice text as hard-coded English strings without corresponding translation key lookups are flagged.',
    },
    remediation:
      "Extract all privacy notice text into internationalisation resource files (e.g., en.json, fr.json). Use your project's i18n library (react-i18next, next-intl, etc.) to load the correct locale at runtime. At a minimum, provide translations for all languages in which your product is marketed. Display a fallback language notice if a user's locale is not yet supported.",
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p1-008',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'No Privacy Notice Version Tracking',
    description:
      'The application lacks a mechanism to track which version of the privacy notice each user has acknowledged. Without version tracking it is impossible to demonstrate that users consented to the current version of the notice, undermining SOC2 P1.1 compliance evidence.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'schema'],
    pattern: {
      type: 'regex',
      value:
        'privacy_policy_accepted_at|privacyPolicyAcceptedAt|privacy_version_accepted|policyAcceptedVersion|terms_accepted_version|privacyConsentVersion|consentVersion.*privacy',
      flags: 'i',
      explanation:
        'Looks for database schema fields, ORM model attributes, or API request/response properties that store the version of the privacy notice accepted by each user. Absence of such fields in user-profile schema files or ORM models triggers this rule.',
    },
    remediation:
      'Add a `privacy_policy_version_accepted` (string or semver) and `privacy_policy_accepted_at` (timestamp) field to your user profile schema. Populate these fields when users accept the notice. Expose them via internal audit APIs. Include version acceptance records in your SOC2 evidence pack.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p1-009',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'Missing Accessibility of Privacy Notice',
    description:
      'Privacy notice components lack appropriate ARIA attributes, semantic HTML, or accessibility annotations, making them inaccessible to users relying on assistive technologies. SOC2 P1.1 requires that the privacy notice be understandable and available to all individuals, including those with disabilities.',
    severity: 'medium',
    languages: ['typescript', 'javascript'],
    targets: ['source'],
    pattern: {
      type: 'semgrep',
      value: `rules:
  - id: p1-009-privacy-notice-accessibility
    patterns:
      - pattern-either:
          - pattern: |
              <$COMP ... className=~"privacy" ...>...</$COMP>
          - pattern: |
              <div ... id=~"privacy" ...>...</div>
      - pattern-not: |
          <$COMP ... aria-label=... ...>...</$COMP>
      - pattern-not: |
          <$COMP ... role=... ...>...</$COMP>
    message: Privacy notice component is missing ARIA role or aria-label for accessibility
    languages: [javascript, typescript]
    severity: WARNING`,
      explanation:
        'Identifies JSX/TSX elements whose className or id contains "privacy" but which lack aria-label, role, or aria-describedby attributes. Such elements may be invisible or meaningless to screen-reader users.',
    },
    remediation:
      'Add appropriate ARIA roles (role="region"), aria-labelledby, and aria-describedby attributes to privacy notice components. Ensure the privacy policy page and all inline notices pass WCAG 2.1 AA checks. Use semantic HTML elements (<section>, <article>, <aside>) and ensure sufficient colour contrast for notice text.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p1-010',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'No Just-in-Time Privacy Notices',
    description:
      'The application collects sensitive categories of personal data (location, health, financial) without providing just-in-time (JIT) contextual privacy notices at the precise moment such data is accessed or requested. SOC2 P1.1 requires timely notice; for sensitive data, notice should be provided at the exact moment of collection.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java'],
    targets: ['source'],
    pattern: {
      type: 'regex',
      value:
        'navigator\\.geolocation|getCurrentPosition|requestPermission\\s*\\(|camera|microphone|healthKit|HealthConnect|readFinancialData|getLocation\\s*\\(|getUserLocation',
      flags: 'i',
      explanation:
        'Identifies calls to sensitive device APIs (geolocation, camera, microphone) and sensitive data-access functions. Flags usages not immediately preceded by a JIT notice display (tooltip, modal, inline message) within the same function or code block.',
    },
    remediation:
      'Immediately before requesting access to sensitive data, display a concise just-in-time notice explaining why the data is needed and how it will be used. For geolocation: "We need your location to show nearby services. Your location is not stored." For health data: display a modal with data use details. Obtain explicit consent before proceeding.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p1-011',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'Missing Granular Privacy Controls in UI',
    description:
      'The application does not provide users with granular privacy controls to manage individual data-processing purposes (e.g., separate toggles for analytics, marketing, personalisation). SOC2 P1.1 and associated privacy principles require that individuals be given meaningful choices regarding the collection and use of their personal information.',
    severity: 'medium',
    languages: ['typescript', 'javascript'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        'privacyToggle|privacy-toggle|consentToggle|marketingConsent|analyticsConsent|personalizationConsent|privacyPreferences|privacy[-_]?settings|dataPreferences|consentManagement',
      flags: 'i',
      explanation:
        'Searches for privacy preference or consent toggle components and state variables. Projects with privacy settings pages or consent flows that use a single accept-all checkbox without granular per-purpose toggles, or projects that have no privacy controls at all, are flagged.',
    },
    remediation:
      'Implement a privacy preferences centre with individual toggles for each data-processing purpose: essential (always on), analytics, marketing, personalisation, and any other applicable purposes. Persist user selections server-side and honour them throughout all data-processing workflows. Surface this preferences centre from the footer and the cookie banner.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },
  {
    id: 'p1-012',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'No Privacy Notice in API Terms or Developer Documentation',
    description:
      'API specification files, OpenAPI schemas, or developer-facing configuration files do not include a reference to or summary of the privacy notice applicable to data processed through the API. SOC2 P1.1 notice requirements extend to all channels through which personal data is collected, including programmatic API integrations used by developers and partners.',
    severity: 'low',
    languages: ['any'],
    targets: ['config'],
    pattern: {
      type: 'absence',
      value:
        'privacy|privacyPolicy|privacy_policy|x-privacy-notice|termsOfService.*privacy|privacy.*termsOfService|data protection|GDPR|CCPA',
      flags: 'i',
      explanation:
        'Inspects OpenAPI/Swagger YAML and JSON files, AsyncAPI specs, and API configuration files for references to a privacy policy URL or privacy notice. Specification files containing contact or license blocks but no privacy-related fields are flagged.',
    },
    remediation:
      'Add a `x-privacy-policy` extension field or include the privacy policy URL in the `info.termsOfService` or `info.contact` block of your OpenAPI specification.\n\nExample:\n\ninfo:\n  x-privacy-policy: "https://example.com/privacy"\n  termsOfService: "https://example.com/terms"\n\nInclude a privacy notice summary in API developer documentation describing what personal data the API processes and directing integrators to the full privacy policy.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://owasp.org/www-project-top-ten/',
    ],
  },
  {
    id: 'p1-013',
    criteria: 'P1.1',
    category: 'privacy',
    title: 'Missing Employee Privacy Notice',
    description:
      'The codebase or configuration does not contain an employee privacy notice or any reference to an internal workforce privacy notice. SOC2 P1.1 requires entities to notify all individuals whose personal data is collected, including employees. HR systems, internal portals, and workforce management tools must present an employee-specific privacy notice.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'any'],
    targets: ['source', 'config'],
    pattern: {
      type: 'regex',
      value:
        'employeePrivacyNotice|employee_privacy_notice|workforcePrivacy|workforce_privacy|hrPrivacy|hr_privacy_notice|employeeDataPolicy|staff_privacy|internalPrivacyNotice|hrms.*privacy|privacy.*hrms',
      flags: 'i',
      explanation:
        'Searches for employee-specific privacy notice references in HR system integrations, internal portal source files, and configuration. Files that handle employee personal data (payroll, performance, attendance) without referencing an employee privacy notice are flagged.',
    },
    remediation:
      'Draft and publish a separate employee privacy notice that covers the categories of employee data collected (payroll, performance reviews, device monitoring, access logs), the purposes for collection, retention periods, and employee rights under applicable law. Reference this notice from the HR portal login screen, onboarding workflows, and any internal tool that processes employee personal data. Store acknowledgement records in your HR system.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },
];
