/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import {
	cc1Rules, cc2Rules, cc3Rules, cc4Rules, cc5Rules,
	cc6Rules, cc7Rules, cc8Rules, cc9Rules,
} from './rules/security/index.js';
import { a1CapacityRules, a1RecoveryRules, a1TestingRules } from './rules/availability/index.js';
import {
	pi1InputRules, pi1ProcessingRules, pi1AccuracyRules,
	pi1ErrorRules, pi1ReviewRules,
} from './rules/integrity/index.js';
import { c1ClassificationRules, c1DisposalRules } from './rules/confidentiality/index.js';
import {
	p1Rules, p2Rules, p3Rules, p4Rules,
	p5Rules, p6Rules, p7Rules, p8Rules,
} from './rules/privacy/index.js';
import type { ISoc2Rule } from './types.js';

export type { ISoc2Rule, Soc2Category, Severity, Language, RuleTarget, IDetectionPattern } from './types.js';

export const SOC2_RULES: ISoc2Rule[] = [
	...cc1Rules, ...cc2Rules, ...cc3Rules, ...cc4Rules, ...cc5Rules,
	...cc6Rules, ...cc7Rules, ...cc8Rules, ...cc9Rules,
	...a1CapacityRules, ...a1RecoveryRules, ...a1TestingRules,
	...pi1InputRules, ...pi1ProcessingRules, ...pi1AccuracyRules, ...pi1ErrorRules, ...pi1ReviewRules,
	...c1ClassificationRules, ...c1DisposalRules,
	...p1Rules, ...p2Rules, ...p3Rules, ...p4Rules,
	...p5Rules, ...p6Rules, ...p7Rules, ...p8Rules,
];

export const SOC2_FRAMEWORK = {
	id: 'soc2',
	name: 'SOC 2 Trust Services Criteria',
	version: '2017',
	publisher: 'AICPA',
	categories: ['security', 'availability', 'integrity', 'confidentiality', 'privacy'] as const,
	rules: SOC2_RULES,
	ruleCount: SOC2_RULES.length,
} as const;
