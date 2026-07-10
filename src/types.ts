/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

export type Soc2Category =
	| 'security'
	| 'availability'
	| 'integrity'
	| 'confidentiality'
	| 'privacy';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Language =
	| 'typescript'
	| 'javascript'
	| 'python'
	| 'java'
	| 'go'
	| 'rust'
	| 'ruby'
	| 'php'
	| 'csharp'
	| 'c'
	| 'cpp'
	| 'any';

export type RuleTarget =
	| 'source'
	| 'config'
	| 'iac'
	| 'cicd'
	| 'dockerfile'
	| 'kubernetes'
	| 'migration'
	| 'schema';

export type PatternType = 'regex' | 'ast' | 'absence' | 'semgrep';

export interface IDetectionPattern {
	type: PatternType;
	value: string;
	flags?: string;
	explanation: string;
}

export interface ISoc2Rule {
	id: string;
	criteria: string;
	category: Soc2Category;
	title: string;
	description: string;
	severity: Severity;
	languages: Language[];
	targets: RuleTarget[];
	pattern: IDetectionPattern;
	remediation: string;
	references: string[];
}
