# @neuralinverse/soc2

SOC 2 Trust Services Criteria rules for the [NeuralInverse](https://neuralinverse.com) static analysis engine.

## Overview

This package provides a complete, structured set of SOC 2 Trust Services Criteria rules detectable via static analysis of source code, configuration files, infrastructure-as-code, Dockerfiles, CI/CD pipelines, and database migrations.

## Coverage

| Category | Criteria | Status |
|----------|----------|--------|
| Security | CC1–CC9 | In progress |
| Availability | A1 | In progress |
| Processing Integrity | PI1 | In progress |
| Confidentiality | C1 | In progress |
| Privacy | P1–P8 | In progress |

## Installation

```bash
npm install @neuralinverse/soc2
```

## Usage

```typescript
import { SOC2_FRAMEWORK, SOC2_RULES } from '@neuralinverse/soc2';

// All rules
console.log(SOC2_RULES.length);

// Framework metadata
console.log(SOC2_FRAMEWORK.name); // "SOC 2 Trust Services Criteria"

// Filter by category
const securityRules = SOC2_RULES.filter(r => r.category === 'security');

// Filter by severity
const critical = SOC2_RULES.filter(r => r.severity === 'critical');

// Filter by language
const pythonRules = SOC2_RULES.filter(r => r.languages.includes('python'));
```

## Rule Shape

```typescript
interface ISoc2Rule {
    id: string;           // e.g. 'soc2-cc6-001'
    criteria: string;     // e.g. 'CC6.1'
    category: Soc2Category;
    title: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    languages: Language[];
    targets: RuleTarget[]; // 'source' | 'config' | 'iac' | 'cicd' | 'dockerfile' | 'kubernetes' | 'migration' | 'schema'
    pattern: IDetectionPattern;
    remediation: string;
    references: string[];
}
```

## License

Business Source License 1.1 — see [LICENSE](./LICENSE).

Change Date: 2029-01-01 | Change License: GPL v2.0

For commercial licensing: [legal@neuralinverse.com](mailto:legal@neuralinverse.com)

## Links

- [NeuralInverse](https://neuralinverse.com)
- [npm](https://www.npmjs.com/package/@neuralinverse/soc2)
- [GitHub](https://github.com/NeuralInverse/soc2)
- [Issues](https://github.com/NeuralInverse/soc2/issues)
