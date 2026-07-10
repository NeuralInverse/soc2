/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const cc6Rules: ISoc2Rule[] = [
	{
		id: 'soc2-cc6-001',
		criteria: 'CC6.1',
		category: 'security',
		title: 'Hardcoded password in source code',
		description: 'A password or credential is assigned as a string literal directly in source code',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?i)(password|passwd|pwd|secret|api_key|apikey|token)\\s*[:=]\\s*["\'][^"\'\\s]{3,}["\']',
			flags: 'i',
			explanation: 'Matches credential variable assignments with non-empty string literals',
		},
		remediation: 'Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Never commit credentials to source control.',
		references: ['CC6.1', 'CC6.6'],
	},
	{
		id: 'soc2-cc6-002',
		criteria: 'CC6.1',
		category: 'security',
		title: 'TLS certificate validation disabled',
		description: 'TLS/SSL certificate verification is explicitly disabled, allowing MITM attacks',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'go', 'java'],
		targets: ['source', 'config'],
		pattern: {
			type: 'regex',
			value: '(verify\\s*=\\s*False|NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*["\']0["\']|InsecureSkipVerify\\s*:\\s*true|CURLOPT_SSL_VERIFYPEER\\s*,\\s*false)',
			explanation: 'Matches common patterns for disabling TLS certificate validation across languages',
		},
		remediation: 'Always validate TLS certificates in production. Use proper CA certificates and never disable verification.',
		references: ['CC6.1', 'CC6.6', 'CC5.2'],
	},
	// TODO: add remaining ~80+ CC6 rules
];
