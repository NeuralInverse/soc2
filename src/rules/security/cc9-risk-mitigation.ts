/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc9Rules: ISoc2Rule[] = [
  // ─── CC9.1 – Risk Mitigation Strategies ──────────────────────────────────────

  {
    id: 'cc9-001',
    criteria: 'CC9.1',
    category: 'security',
    title: 'Missing Vendor Security Assessment Hooks',
    description:
      'CI/CD pipelines lack any vendor or third-party security assessment step. Without automated hooks that trigger vendor security reviews, unvetted third parties can be introduced into the supply chain without oversight.',
    severity: 'high',
    languages: ['any'],
    targets: ['cicd'],
    pattern: {
      type: 'absence',
      value:
        '(vendor[_-]?security|third[_-]?party[_-]?assessment|supplier[_-]?review|vendor[_-]?scan|third[_-]?party[_-]?scan)',
      flags: 'i',
      explanation:
        'Checks that a vendor/third-party security assessment step is present in CI/CD pipeline definitions. Absence indicates no automated vendor risk gating.',
    },
    remediation:
      'Add a dedicated vendor security assessment stage to your CI/CD pipeline. Use tools such as FOSSA, Snyk, or Black Duck to automate third-party evaluations before dependencies are approved. Gate merges on successful assessment results.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },

  {
    id: 'cc9-002',
    criteria: 'CC9.1',
    category: 'security',
    title: 'No Third-Party Risk Management Configuration',
    description:
      'No third-party risk management (TPRM) configuration file or policy block is present in the repository. Without a documented TPRM policy, vendor risks cannot be systematically assessed, tracked, or mitigated.',
    severity: 'high',
    languages: ['any'],
    targets: ['config'],
    pattern: {
      type: 'absence',
      value:
        '(tprm|third[_-]?party[_-]?risk|vendor[_-]?risk[_-]?management|supplier[_-]?risk)',
      flags: 'i',
      explanation:
        'Looks for TPRM-related keys or sections in configuration files. Absence signals no formalised vendor risk management configuration is in place.',
    },
    remediation:
      'Create a TPRM configuration file (e.g., tprm-policy.yaml) that enumerates approved vendors, risk tiers, assessment cadences, and remediation SLAs. Integrate this file into onboarding and change-management workflows.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },

  {
    id: 'cc9-003',
    criteria: 'CC9.1',
    category: 'security',
    title: 'Missing SLA Enforcement Configuration',
    description:
      'Service Level Agreement (SLA) enforcement settings are absent from service or infrastructure configuration. Without explicit SLA timeouts, retries, and breach-handling logic, vendor performance obligations cannot be automatically enforced.',
    severity: 'medium',
    languages: ['any'],
    targets: ['config', 'iac'],
    pattern: {
      type: 'absence',
      value:
        '(sla[_-]?timeout|sla[_-]?threshold|sla[_-]?enforcement|service[_-]?level[_-]?agreement)',
      flags: 'i',
      explanation:
        'Detects missing SLA-related configuration keys in service definitions or IaC templates.',
    },
    remediation:
      'Define SLA thresholds (availability %, response times, RTO/RPO) in your service configuration and IaC templates. Implement automated breach alerts using your monitoring stack (e.g., PagerDuty, OpsGenie) and document escalation procedures.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },

  {
    id: 'cc9-004',
    criteria: 'CC9.1',
    category: 'security',
    title: 'No Supplier Security Requirements Defined',
    description:
      'Infrastructure or configuration files contain no supplier security requirement declarations. Suppliers without explicit security obligations may expose the organisation to uncontrolled risk.',
    severity: 'high',
    languages: ['any'],
    targets: ['config', 'iac'],
    pattern: {
      type: 'absence',
      value:
        '(supplier[_-]?security|vendor[_-]?security[_-]?requirements?|third[_-]?party[_-]?security[_-]?requirements?)',
      flags: 'i',
      explanation:
        'Checks for supplier security requirement keys in configuration or IaC. Absence means no security requirements have been codified for suppliers.',
    },
    remediation:
      'Document minimum security requirements for all suppliers (e.g., SOC 2 Type II, ISO 27001 certification, penetration testing evidence). Encode these as policy checks in your TPRM workflow and require sign-off before onboarding.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://www.iso.org/isoiec-27001-information-security.html',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },

  {
    id: 'cc9-005',
    criteria: 'CC9.1',
    category: 'security',
    title: 'Missing Contractual Security Clauses',
    description:
      'Contract or agreement template files contain no security clause references. Contracts that omit data protection, breach notification, audit rights, or liability clauses leave the organisation without enforceable protections against vendor failures.',
    severity: 'high',
    languages: ['any'],
    targets: ['config'],
    pattern: {
      type: 'absence',
      value:
        '(data[_-]?protection[_-]?clause|security[_-]?clause|breach[_-]?notification|audit[_-]?rights?|liability[_-]?clause)',
      flags: 'i',
      explanation:
        'Looks for mandatory security clause markers in contract or policy configuration files.',
    },
    remediation:
      'Embed standard security clauses in all vendor contracts: data protection obligations, incident and breach notification windows (e.g., 72 hours per GDPR), right-to-audit provisions, and clear liability and indemnification terms.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://www.iso.org/isoiec-27001-information-security.html',
      'https://owasp.org/www-project-top-ten/',
    ],
  },

  {
    id: 'cc9-006',
    criteria: 'CC9.1',
    category: 'security',
    title: 'No Vendor Access Monitoring',
    description:
      'No vendor access monitoring, privileged access management (PAM), or just-in-time (JIT) access patterns are configured. Unmonitored vendor access increases the risk of data exfiltration and unauthorised changes.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        '(vendor[_-]?access[_-]?monitor|pam[_-]?session|jit[_-]?access|privileged[_-]?session|vendor[_-]?session[_-]?record)',
      flags: 'i',
      explanation:
        'Checks for vendor access monitoring or PAM session recording patterns in application source and configuration.',
    },
    remediation:
      'Implement JIT vendor access through a PAM solution (e.g., CyberArk, BeyondTrust, HashiCorp Boundary). Record all vendor sessions, enforce MFA, and alert on anomalous access patterns using SIEM integration.',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },

  {
    id: 'cc9-007',
    criteria: 'CC9.1',
    category: 'security',
    title: 'Missing Fourth-Party Risk Tracking',
    description:
      'No fourth-party (sub-processor or sub-contractor) risk tracking configuration is present. Risks inherited from vendors\' own supply chains are invisible without explicit fourth-party tracking.',
    severity: 'medium',
    languages: ['any'],
    targets: ['config'],
    pattern: {
      type: 'absence',
      value:
        '(fourth[_-]?party|sub[_-]?processor|sub[_-]?contractor[_-]?risk|nth[_-]?party)',
      flags: 'i',
      explanation:
        'Detects absence of fourth-party or sub-processor risk configuration entries.',
    },
    remediation:
      'Extend your TPRM programme to include fourth-party mapping. Require primary vendors to disclose their key sub-processors. Use a supply-chain risk intelligence platform (e.g., Prevalent, ProcessUnity) to monitor cascading risks.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },

  {
    id: 'cc9-008',
    criteria: 'CC9.1',
    category: 'security',
    title: 'Unvetted Open Source Dependencies',
    description:
      'Package manifests include dependencies that are fetched without integrity verification (no lockfile hash, no signature check). Unvetted open-source packages can introduce malicious code into the supply chain.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php'],
    targets: ['config', 'cicd'],
    pattern: {
      type: 'regex',
      value:
        '(npm\\s+install(?!\\s+--ignore-scripts)|pip\\s+install(?!\\s+-r\\s+requirements\\.txt\\s+--require-hashes)|gem\\s+install(?!\\s+--trust-policy))',
      flags: 'gim',
      explanation:
        'Detects package install commands that bypass integrity or hash verification, indicating dependencies may not be vetted before installation.',
    },
    remediation:
      'Enforce lockfile-based installs (npm ci, pip install --require-hashes, bundler --frozen). Enable Sigstore/Cosign signature verification. Use a private artifact registry (Artifactory, Nexus) with quarantine policies for new packages.',
    references: [
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
    ],
  },

  {
    id: 'cc9-009',
    criteria: 'CC9.1',
    category: 'security',
    title: 'Missing Software Bill of Materials (SBOM)',
    description:
      'No SBOM generation step is present in the build or release pipeline. Without an SBOM, the organisation cannot quickly identify affected components when a new vulnerability is disclosed in the supply chain.',
    severity: 'high',
    languages: ['any'],
    targets: ['cicd', 'dockerfile'],
    pattern: {
      type: 'absence',
      value:
        '(sbom|software[_-]?bill[_-]?of[_-]?materials|syft|cyclonedx|spdx)',
      flags: 'i',
      explanation:
        'Checks for SBOM generation tooling (Syft, CycloneDX, SPDX) in pipeline or container build definitions.',
    },
    remediation:
      'Integrate SBOM generation into every build using Syft or cdxgen to produce CycloneDX or SPDX documents. Publish SBOMs as build artefacts and ingest them into a vulnerability management platform (e.g., DependencyTrack, Grype).',
    references: [
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
    ],
  },

  {
    id: 'cc9-010',
    criteria: 'CC9.1',
    category: 'security',
    title: 'No License Compliance Checking',
    description:
      'CI/CD pipelines contain no open-source license compliance scan. Including dependencies with incompatible licenses (e.g., AGPL, SSPL) can expose the organisation to legal liability and force unintended source disclosure.',
    severity: 'medium',
    languages: ['any'],
    targets: ['cicd'],
    pattern: {
      type: 'absence',
      value:
        '(license[_-]?check|license[_-]?compliance|fossa|scancode|licensecheck|\\bort\\b)',
      flags: 'i',
      explanation:
        'Detects missing license compliance scanning steps in CI/CD pipeline definitions.',
    },
    remediation:
      'Add a license compliance scan stage using FOSSA, ORT, or ScanCode. Define an approved license allowlist and block builds that introduce prohibited licenses. Store compliance reports as pipeline artefacts for audit purposes.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },

  // ─── CC9.2 – Business Disruption Risk ────────────────────────────────────────

  {
    id: 'cc9-011',
    criteria: 'CC9.2',
    category: 'security',
    title: 'Missing Disaster Recovery Configuration',
    description:
      'Infrastructure-as-code or service configuration contains no disaster recovery (DR) settings such as RTO, RPO, backup schedules, or failover targets. Without DR configuration, services lack automated recovery capabilities after a disruption.',
    severity: 'critical',
    languages: ['any'],
    targets: ['iac', 'config'],
    pattern: {
      type: 'absence',
      value:
        '(disaster[_-]?recovery|failover[_-]?target|\\brto\\b|\\brpo\\b|backup[_-]?schedule|dr[_-]?region)',
      flags: 'i',
      explanation:
        'Checks for disaster recovery parameters (RTO, RPO, failover, backup schedule) in IaC and service configurations.',
    },
    remediation:
      'Define DR objectives (RTO <= 4 h, RPO <= 1 h) in IaC. Configure automated cross-region backups, failover routing (Route 53 health checks, Azure Traffic Manager), and runbook automation. Test DR procedures at least annually.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },

  {
    id: 'cc9-012',
    criteria: 'CC9.2',
    category: 'security',
    title: 'No Business Continuity Plan References',
    description:
      'No business continuity plan (BCP) references, runbook links, or continuity policy identifiers are present in repository configuration or IaC. Teams cannot follow established recovery procedures if they are not discoverable from the deployment artefacts.',
    severity: 'high',
    languages: ['any'],
    targets: ['config', 'iac'],
    pattern: {
      type: 'absence',
      value:
        '(business[_-]?continuity|bcp[_-]?plan|continuity[_-]?runbook|incident[_-]?runbook)',
      flags: 'i',
      explanation:
        'Looks for BCP references or runbook links in configuration and IaC files.',
    },
    remediation:
      'Add BCP runbook links to service metadata in your IaC (e.g., as resource tags or README sections). Store runbooks in a version-controlled wiki (Confluence, Notion) and reference them from deployment configuration files.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://www.nist.gov/cyberframework',
      'https://www.iso.org/isoiec-27001-information-security.html',
    ],
  },

  {
    id: 'cc9-013',
    criteria: 'CC9.2',
    category: 'security',
    title: 'Single Point of Failure Pattern Detected',
    description:
      'Source code or configuration exposes single-instance service definitions with no replica or HA configuration. A single-instance deployment is a single point of failure (SPOF) that can cause complete service outages.',
    severity: 'critical',
    languages: ['typescript', 'javascript', 'python', 'java', 'go'],
    targets: ['source', 'kubernetes', 'iac'],
    pattern: {
      type: 'regex',
      value:
        '(replicas:\\s*["\']?1["\']?\\s*$|instance_count\\s*=\\s*1\\s*$|desired_count\\s*=\\s*1\\s*$)',
      flags: 'gim',
      explanation:
        'Detects single-replica or single-instance declarations in Kubernetes manifests and IaC that create a single point of failure.',
    },
    remediation:
      'Set replicas/instance_count to a minimum of 2 (preferably 3 or more) for production workloads. Use pod disruption budgets in Kubernetes (minAvailable: 1) and auto-scaling groups with a minimum of 2 instances in cloud IaC.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },

  {
    id: 'cc9-014',
    criteria: 'CC9.2',
    category: 'security',
    title: 'Missing Redundancy Configuration',
    description:
      'Infrastructure definitions lack redundancy settings such as multi-AZ deployment, replication factors, or standby instances. Non-redundant infrastructure cannot sustain availability during partial failures.',
    severity: 'high',
    languages: ['any'],
    targets: ['iac', 'config', 'kubernetes'],
    pattern: {
      type: 'absence',
      value:
        '(multi[_-]?az|availability[_-]?zones?|replication[_-]?factor|standby[_-]?instance|redundan)',
      flags: 'i',
      explanation:
        'Checks for multi-AZ, replication factor, or standby configuration in IaC and Kubernetes manifests.',
    },
    remediation:
      'Enable multi-AZ deployments for all stateful services (RDS Multi-AZ, ElastiCache cluster mode, DynamoDB global tables). Set replication factors >= 3 for message brokers and distributed databases. Document redundancy topology in architecture diagrams.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.cisecurity.org/cis-benchmarks',
    ],
  },

  {
    id: 'cc9-015',
    criteria: 'CC9.2',
    category: 'security',
    title: 'No Geographic Distribution Configured',
    description:
      'Services are deployed in a single region with no cross-region replication or geographic distribution. A regional outage would render all services unavailable, violating availability commitments.',
    severity: 'high',
    languages: ['any'],
    targets: ['iac', 'config'],
    pattern: {
      type: 'absence',
      value:
        '(cross[_-]?region|geo[_-]?replication|multi[_-]?region|secondary[_-]?region|global[_-]?distribution)',
      flags: 'i',
      explanation:
        'Detects absence of cross-region or geographic distribution configuration in IaC templates.',
    },
    remediation:
      'Implement active-active or active-passive multi-region deployments using global load balancers (AWS Global Accelerator, Azure Front Door, Cloudflare). Configure cross-region database replication and CDN with geographic failover for static assets.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },

  {
    id: 'cc9-016',
    criteria: 'CC9.2',
    category: 'security',
    title: 'Missing Circuit Breaker Pattern',
    description:
      'Service-to-service calls are made without circuit breaker logic. Without circuit breakers, cascading failures from downstream service degradation can overwhelm upstream services and cause system-wide outages.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source'],
    pattern: {
      type: 'absence',
      value:
        '(circuit[_-]?breaker|CircuitBreaker|opossum|resilience4j|Polly\\.CircuitBreaker|hystrix|gobreaker)',
      flags: 'i',
      explanation:
        'Checks for circuit breaker library usage or patterns in service source code. Absence indicates no circuit breaker protection.',
    },
    remediation:
      'Implement circuit breakers on all external and inter-service HTTP/gRPC calls using language-appropriate libraries (opossum for Node.js, resilience4j for Java, Polly for .NET, gobreaker for Go). Configure open/half-open/closed thresholds and fallback responses.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },

  {
    id: 'cc9-017',
    criteria: 'CC9.2',
    category: 'security',
    title: 'No Fallback Mechanism Implemented',
    description:
      'External API calls and critical service integrations lack fallback logic (cached responses, default values, or alternative providers). Missing fallbacks mean any third-party outage directly causes user-facing failures.',
    severity: 'high',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp', 'ruby'],
    targets: ['source'],
    pattern: {
      type: 'semgrep',
      value: [
        'rules:',
        '  - id: cc9-017-no-fallback',
        '    patterns:',
        '      - pattern: |',
        '          $RESP = await $CLIENT.$METHOD(...)',
        '      - pattern-not: |',
        '          try { ... } catch (...) { $FALLBACK }',
        '      - pattern-not: |',
        '          $RESP = await $CLIENT.$METHOD(...).catch(...)',
        '    message: External call without fallback handler detected',
        '    languages: [typescript, javascript]',
        '    severity: WARNING',
      ].join('\n'),
      explanation:
        'Detects async external service calls that do not have a corresponding catch block or fallback handler to handle downstream failures gracefully.',
    },
    remediation:
      'Wrap all external calls in try/catch or .catch() handlers that return stale cached data, a safe default, or an alternative provider response. Use a cache-aside pattern (Redis, Memcached) to serve last-known-good responses during outages.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://owasp.org/www-project-top-ten/',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    ],
  },

  {
    id: 'cc9-018',
    criteria: 'CC9.2',
    category: 'security',
    title: 'Missing Service Degradation Handling',
    description:
      'Application code does not implement graceful degradation (feature flags, reduced-functionality modes, or health-check-driven load shedding). Without degradation handling, partial failures cascade into complete service unavailability.',
    severity: 'medium',
    languages: ['typescript', 'javascript', 'python', 'java', 'go', 'csharp'],
    targets: ['source', 'config'],
    pattern: {
      type: 'absence',
      value:
        '(graceful[_-]?degradation|feature[_-]?flag|feature[_-]?toggle|load[_-]?shed|health[_-]?check[_-]?fail|degraded[_-]?mode|maintenance[_-]?mode)',
      flags: 'i',
      explanation:
        'Checks for graceful degradation patterns such as feature flags, load shedding, or degraded-mode handlers in source and configuration.',
    },
    remediation:
      'Implement feature flags (LaunchDarkly, Unleash, or homegrown) to disable non-critical features under load. Add health-check endpoints that return degraded status when dependencies are unhealthy. Configure load shedding via rate limiting and queue depth thresholds.',
    references: [
      'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
      'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      'https://www.nist.gov/cyberframework',
    ],
  },
];
