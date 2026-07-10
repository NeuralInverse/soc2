/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const a1TestingRules: ISoc2Rule[] = [
	{
		id: 'a1-test-001',
		criteria: 'A1.3',
		category: 'availability',
		title: 'Missing Chaos Engineering Configuration',
		description:
			'No chaos engineering framework configuration was detected in the repository. Chaos engineering (e.g., Chaos Monkey, Gremlin, LitmusChaos) is required to proactively test system resilience by deliberately injecting failures. Without it, hidden availability weaknesses remain undetected until production incidents occur.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'(chaos(?:monkey|toolkit|blade|mesh)|gremlin\\.ya?ml|litmus(?:chaos)?|pumba|toxiproxy|fault(?:injection|-inject)|chaosengineering)',
			flags: 'i',
			explanation:
				'Checks for the absence of any chaos engineering tool configuration file or reference. Matches common chaos frameworks: Chaos Monkey, Chaos Toolkit, ChaosBlade, Gremlin, LitmusChaos, Pumba, Toxiproxy.',
		},
		remediation:
			'Introduce a chaos engineering practice using a framework such as LitmusChaos, Chaos Toolkit, or Gremlin. Define experiment manifests in version control, schedule regular game days, and integrate chaos runs into your CI/CD pipeline. Document blast radius, hypothesis, and rollback procedures for every experiment.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-test-002',
		criteria: 'A1.3',
		category: 'availability',
		title: 'No Load Testing Step in CI Pipeline',
		description:
			'The CI/CD pipeline configuration contains no load-testing step. Load testing (e.g., k6, Locust, JMeter, Artillery, Gatling) validates that the system meets throughput and latency targets before release. Deploying without load testing risks capacity surprises under production traffic.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd'],
		pattern: {
			type: 'absence',
			value:
				'\\b(k6|locust|jmeter|artillery|gatling|vegeta|wrk2?|hey|load[_-]test(?:ing)?|perf[_-]test(?:ing)?|benchmark[_-]run)\\b',
			flags: 'i',
			explanation:
				'Detects absence of load-testing tool invocations inside CI pipeline files. Covers k6, Locust, JMeter, Artillery, Gatling, Vegeta, wrk/wrk2, hey, and generic load-test/perf-test step names.',
		},
		remediation:
			'Add a dedicated load-testing stage to your CI pipeline that runs a representative workload scenario. Gate deployments on passing performance thresholds (p95 latency, error rate, throughput). Store results as pipeline artifacts and alert on regressions.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-test-003',
		criteria: 'A1.3',
		category: 'availability',
		title: 'Missing Performance Benchmarks',
		description:
			'No performance benchmark definitions were found in source or configuration files. Performance benchmarks establish measurable baselines for response time, throughput, and resource utilisation. Without defined baselines, regressions cannot be detected automatically and availability degradation goes unnoticed.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'rust', 'csharp'],
		targets: ['source', 'config', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'\\b(benchmark(?:Suite|Test|Result|Options|Runner)?|BenchmarkFunc|bench_test\\.go|criterion|hyperfine|perf\\.mark|performance\\.mark|PerformanceObserver|timing(?:Budget|Threshold)|latency(?:Budget|SLO|Target)|throughput(?:Target|SLO))\\b',
			flags: 'i',
			explanation:
				'Looks for absence of benchmark harness constructs across languages: Go bench_test, Rust criterion, JS performance.mark/PerformanceObserver, generic benchmark suite patterns, latency/throughput SLO constants.',
		},
		remediation:
			'Define performance benchmarks alongside unit tests for critical paths. Encode SLO targets (p50, p95, p99 latency; requests/sec) as assertions that fail CI when breached. Use tools such as Criterion (Rust), benchmark (Go), or k6 thresholds and store historical results to surface trends.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-test-004',
		criteria: 'A1.3',
		category: 'availability',
		title: 'No Stress Testing Requirements Defined',
		description:
			'No stress or soak testing configuration was found. Stress testing pushes the system beyond its expected peak load to locate the breaking point, while soak testing verifies stability over extended periods. The absence of these tests leaves memory leaks, thread exhaustion, and resource saturation undetected.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'\\b(stress[_-]test(?:ing)?|soak[_-]test(?:ing)?|endurance[_-]test(?:ing)?|spike[_-]test(?:ing)?|breakpoint[_-]test(?:ing)?|ramping[_\\-]?vus|stages:\\s*\\[|load[_-]profile)\\b',
			flags: 'i',
			explanation:
				'Checks for absence of stress/soak test configurations. Matches stress-test, soak-test, endurance-test, spike-test, breakpoint-test step names, and k6 ramping VU / stage configuration blocks.',
		},
		remediation:
			'Define stress and soak test scenarios as code. For stress tests, gradually ramp load past expected peak until errors appear and record the breaking point. For soak tests, sustain normal load for 24–72 hours monitoring memory, file descriptors, and database connection pools. Gate releases on passing soak runs in staging.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'a1-test-005',
		criteria: 'A1.3',
		category: 'availability',
		title: 'Missing Failover Testing',
		description:
			'No failover test definitions or automation were detected. Failover testing verifies that the system automatically or manually switches to a standby component (database replica, secondary region, backup service) within the defined RTO when a primary component fails. Untested failover paths often fail silently during real incidents.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config', 'cicd', 'iac'],
		pattern: {
			type: 'absence',
			value:
				'\\b(failover[_-]?test(?:ing)?|ha[_-]?test(?:ing)?|high[_\\-]availability[_\\-]test|promote[_-]replica|replica[_-]failover|rds[_-]failover|aurora[_-]failover|cluster[_-]failover|switchover[_-]test)\\b',
			flags: 'i',
			explanation:
				'Detects absence of failover test automation. Matches generic failover-test keywords and cloud-specific terms such as RDS failover, Aurora failover, promote-replica, and cluster switchover test references.',
		},
		remediation:
			'Implement automated failover tests that simulate primary component failure (kill primary DB, terminate primary node, block primary AZ). Validate that traffic shifts within the RTO, data loss is within RPO, health checks reflect the new primary, and alerts fire correctly. Run these tests quarterly or on every infrastructure change.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'a1-test-006',
		criteria: 'A1.3',
		category: 'availability',
		title: 'No Disaster Recovery Drill Schedule',
		description:
			'No DR drill schedule or automation was found in repository configuration or CI/CD pipelines. Regular DR drills are required by SOC 2 A1.3 to validate that documented recovery procedures are executable, RTO/RPO targets are achievable, and teams are familiar with recovery steps under pressure.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'\\b(dr[_-]drill|disaster[_-]recovery[_-](drill|test|exercise|simulation)|runbook[_-]test|recovery[_-]drill|bc[_-]?dr[_-]?(test|drill|exercise)|tabletop[_-]exercise|rto[_-]test|rpo[_-]test)\\b',
			flags: 'i',
			explanation:
				'Checks for absence of DR drill scheduling or automation keywords. Matches dr-drill, disaster-recovery-drill, bcdr-test, tabletop-exercise, rto-test, rpo-test, and similar recovery exercise identifiers.',
		},
		remediation:
			'Schedule DR drills at least twice per year. Automate drill execution where possible using runbooks stored in version control. Each drill must verify: backup restoration within RPO, service restoration within RTO, DNS/routing failover, cross-region database promotion, and stakeholder notification. Record results and remediate gaps before the next drill.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-test-007',
		criteria: 'A1.3',
		category: 'availability',
		title: 'Missing Game Day Procedures',
		description:
			'No game day procedure documents, scripts, or scheduling references were found. Game days are structured exercises where engineering teams deliberately cause failures in controlled environments to validate system resilience and improve incident response. Their absence indicates a gap in proactive availability assurance.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'\\b(game[_-]?day|gameday|fire[_-]?drill|resilience[_-]?exercise|wheel[_-]?of[_-]?misfortune|failure[_-]?mode[_-]?exercise|failure[_-]?injection[_-]?exercise|chaos[_-]?day|reliability[_-]?drill)\\b',
			flags: 'i',
			explanation:
				'Checks for absence of game day or resilience exercise references. Matches gameday, fire-drill, wheel-of-misfortune, failure-mode-exercise, chaos-day, and reliability-drill naming conventions.',
		},
		remediation:
			'Establish a game day program with quarterly scheduled exercises. Create runbooks in version control for each game day scenario (region failure, database corruption, certificate expiry, dependency outage). Assign roles (incident commander, scribe, comms lead), define success criteria, and conduct post-mortems. Track action items to closure.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-test-008',
		criteria: 'A1.3',
		category: 'availability',
		title: 'No Availability SLA Tests',
		description:
			'No SLA or SLO validation tests were detected in source or CI configuration. SLA tests programmatically assert that uptime commitments, error budgets, and latency targets are met. Without them, SLA breaches may go undetected until customer-facing impact is reported.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'any'],
		targets: ['source', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'\\b(sla[_-]?test(?:ing)?|slo[_-]?test(?:ing)?|uptime[_-]?assert(?:ion)?|availability[_-]?assert(?:ion)?|error[_-]?budget[_-]?(test|check|assert)|uptime[_-]?threshold|sla[_-]?check|slo[_-]?compliance)\\b',
			flags: 'i',
			explanation:
				'Detects absence of SLA/SLO test constructs. Matches sla-test, slo-test, uptime-assert, availability-assertion, error-budget-test/check, uptime-threshold, and slo-compliance patterns.',
		},
		remediation:
			'Implement SLO tests that query your observability platform (Prometheus, Datadog, CloudWatch) for historical availability metrics and assert they meet contractual thresholds. Run these tests in CI against staging environments and generate compliance reports. Integrate error budget burn rate alerts into your incident response workflow.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'a1-test-009',
		criteria: 'A1.3',
		category: 'availability',
		title: 'Missing Uptime Monitoring Configuration',
		description:
			'No uptime monitoring configuration was found. Uptime monitoring continuously checks service endpoints from external vantage points and alerts on downtime within seconds. Without it, service unavailability may go undetected or be discovered only by customers.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config', 'iac', 'cicd'],
		pattern: {
			type: 'regex',
			value:
				'(?:uptimerobot|pingdom|statuscake|freshping|better[_-]?uptime|site24x7|datadog[_-]synthetics|newrelic[_-]synthetics|cloudwatch[_-]synthetics|uptime(?:_check|Check|Monitor|_monitor)|health[_-]?check[_-]?url|external[_-]?monitor)',
			flags: 'i',
			explanation:
				'Searches for uptime monitoring service references in configuration and IaC files. Matches UptimeRobot, Pingdom, StatusCake, Freshping, Better Uptime, Site24x7, Datadog Synthetics, New Relic Synthetics, CloudWatch Synthetics, and generic uptime-check/health-check-url patterns.',
		},
		remediation:
			'Configure uptime monitoring for all public and internal service endpoints using a dedicated external monitoring service. Set check intervals no greater than 60 seconds, configure multi-location checks to avoid false positives, and integrate alerts into your incident management workflow (PagerDuty, OpsGenie). Define an SLA for mean-time-to-detect (MTTD) of no more than 2 minutes.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-test-010',
		criteria: 'A1.3',
		category: 'availability',
		title: 'No Synthetic Monitoring Configuration',
		description:
			'No synthetic monitoring scripts or configuration were detected. Synthetic monitoring simulates real user transactions (login, checkout, API calls) from external locations to proactively detect availability and performance degradation before real users are affected. Its absence creates blind spots in user-journey availability.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'any'],
		targets: ['config', 'source', 'cicd'],
		pattern: {
			type: 'regex',
			value:
				'(?:synthetic(?:_|-)?(?:monitor(?:ing)?|test|check|transaction)|canary[_-]?(?:test|script|monitor)|heartbeat[_-]?(?:test|monitor|check)|browser[_-]?test[_-]?(?:monitor|check)|playwright[_-]?monitor|puppeteer[_-]?monitor|selenium[_-]?monitor|datadog[_-]?canary|newrelic[_-]?scripted[_-]?browser|cloudwatch[_-]?canary)',
			flags: 'i',
			explanation:
				'Detects synthetic monitoring configuration. Matches synthetic-monitor, canary-test, heartbeat-monitor, browser-test-monitor, Playwright/Puppeteer/Selenium monitor references, Datadog canary, New Relic scripted browser, and CloudWatch canary patterns.',
		},
		remediation:
			'Implement synthetic monitoring for critical user journeys using a tool such as Datadog Synthetics, New Relic Scripted Browser, or CloudWatch Synthetics. Define step-by-step transaction scripts covering authentication, core workflows, and checkout/payment paths. Run checks every 5 minutes from multiple geographic locations and alert on failure or SLA breach.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-test-011',
		criteria: 'A1.3',
		category: 'availability',
		title: 'Missing End-to-End Availability Tests',
		description:
			'No end-to-end (E2E) availability test suite was found. E2E tests validate that the complete user-facing system—spanning frontend, APIs, databases, and third-party integrations—is available and functional. Without E2E availability tests, partial outages affecting user experience may not be detected by component-level health checks.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source', 'cicd'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: a1-test-011-e2e-availability
    patterns:
      - pattern-either:
          - pattern: |
              describe($SUITE, () => { ... })
          - pattern: |
              test($NAME, async () => { ... })
          - pattern: |
              it($NAME, async () => { ... })
      - pattern-either:
          - pattern-regex: "availability|uptime|end.to.end|e2e|smoke.test|health.check|user.journey"
    message: "E2E availability test detected — ensure coverage exists"
    languages: [javascript, typescript]
    severity: INFO`,
			explanation:
				'Semgrep rule that identifies end-to-end test blocks containing availability, uptime, e2e, smoke-test, health-check, or user-journey keywords. Used in absence mode to confirm such tests exist.',
		},
		remediation:
			'Build an E2E availability test suite using Playwright, Cypress, or Selenium that exercises critical user journeys in a production-like environment. Include smoke tests that run post-deployment to verify the system is operational. Schedule full E2E suites as part of CI and as synthetic monitors in production, and gate deployments on passing smoke tests.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-test-012',
		criteria: 'A1.3',
		category: 'availability',
		title: 'No Degraded Mode Testing',
		description:
			'No degraded mode or graceful degradation tests were found. Systems should continue to serve reduced functionality when non-critical dependencies (caches, recommendation engines, third-party APIs) fail. Without degraded mode testing, failures in non-critical components may cascade into full outages.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'rust', 'csharp'],
		targets: ['source', 'cicd'],
		pattern: {
			type: 'regex',
			value:
				'\\b(degraded[_-]?mode|graceful[_-]?degradation[_-]?test|fallback[_-]?test(?:ing)?|circuit[_-]?breaker[_-]?test|bulkhead[_-]?test|partial[_-]?outage[_-]?test|reduced[_-]?functionality[_-]?test|feature[_-]?flag[_-]?fallback[_-]?test|dependency[_-]?failure[_-]?test)\\b',
			flags: 'i',
			explanation:
				'Detects degraded mode and graceful degradation test constructs. Matches degraded-mode, graceful-degradation-test, fallback-test, circuit-breaker-test, bulkhead-test, partial-outage-test, reduced-functionality-test, and dependency-failure-test patterns.',
		},
		remediation:
			'Write tests that simulate dependency failures (mock external APIs returning 500/timeout, disable cache, simulate database read-replica lag) and assert the system responds with degraded but functional behaviour rather than crashing. Test circuit breaker open/half-open/closed transitions. Include degraded-mode scenarios in load testing to validate performance under partial failures.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-test-013',
		criteria: 'A1.3',
		category: 'availability',
		title: 'Missing Availability Reporting Configuration',
		description:
			'No availability reporting configuration or status page integration was detected. Availability reports provide audit evidence of system uptime, SLA compliance, and incident history required for SOC 2 A1.3. Without automated reporting, availability evidence must be gathered manually, increasing audit risk and the chance of gaps.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'cicd', 'iac'],
		pattern: {
			type: 'absence',
			value:
				'\\b(status(?:page|\.io|_page)|availability[_-]?report(?:ing)?|uptime[_-]?report(?:ing)?|sla[_-]?report(?:ing)?|incident[_-]?report(?:ing)?|cachet|statuspal|instatus|freshstatus|atlassian[_-]?statuspage|opsgenie[_-]?status|pagerduty[_-]?status|uptime[_-]?kuma|availability[_-]?dashboard)\\b',
			flags: 'i',
			explanation:
				'Checks for absence of availability reporting and status page tooling references. Matches Statuspage, Cachet, Statuspal, Instatus, Freshstatus, Atlassian Statuspage, OpsGenie Status, PagerDuty Status, Uptime Kuma, and generic availability-report/sla-report patterns.',
		},
		remediation:
			'Configure automated availability reporting using a status page service (Atlassian Statuspage, Cachet, Uptime Kuma) connected to your monitoring platform. Generate monthly availability reports from observability data (Prometheus, Datadog, CloudWatch) and store them as audit artifacts. Reports must include: uptime percentage per service, incident count and duration, SLA compliance status, and error budget consumption.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
];
