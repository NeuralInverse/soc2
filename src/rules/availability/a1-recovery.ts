/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const a1RecoveryRules: ISoc2Rule[] = [
	{
		id: 'a1-rec-001',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Backup Configuration',
		description:
			'No backup configuration was detected in the codebase or infrastructure definitions. Backup configurations are required to ensure data can be recovered in the event of system failure or data corruption.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config', 'iac', 'kubernetes'],
		pattern: {
			type: 'absence',
			value: '(backup|BackupPlan|aws_backup|azurerm_backup|google_sql_database_instance.*backup_configuration)',
			flags: 'i',
			explanation:
				'Detects absence of backup configuration keywords across IaC, config, and Kubernetes manifests.',
		},
		remediation:
			'Define a backup configuration using your cloud provider (e.g., AWS Backup, Azure Backup, GCP Cloud SQL automated backups) or application-level backup tooling. Ensure backups are scheduled, encrypted, and stored in a durable location.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-002',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Automated Backup Schedule',
		description:
			'Backup schedule automation is missing. Without a scheduled backup policy, backups may be performed inconsistently or forgotten entirely, increasing data loss risk.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'absence',
			value: '(schedule_expression|cron|backup_schedule|retention_period|backup_window)',
			flags: 'i',
			explanation:
				'Checks that a scheduled expression or cron-based backup schedule is defined in infrastructure or config files.',
		},
		remediation:
			'Configure an automated backup schedule using cron expressions or provider-managed scheduling (e.g., AWS Backup rules, Azure Backup policy schedules). Align the schedule with your RPO requirements.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-003',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Backup Encryption',
		description:
			'Backup data is not configured with encryption. Unencrypted backups are vulnerable to unauthorized access if storage is compromised, violating data confidentiality and availability controls.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'regex',
			value:
				'backup[\\s\\S]{0,200}?encrypt\\s*[=:]\\s*["\']?(false|no|0|disabled)["\']?',
			flags: 'im',
			explanation:
				'Detects backup blocks where encryption is explicitly disabled or set to false.',
		},
		remediation:
			'Enable encryption for all backup storage using AES-256 or provider-managed KMS keys. Ensure that encryption is enforced at the backup policy level and that keys are rotated regularly.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'a1-rec-004',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Backup Retention Policy',
		description:
			'A backup retention policy defining how long backups are kept has not been configured. Without retention policies, backups may be overwritten too soon or stored indefinitely at unnecessary cost.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'absence',
			value: '(retention|delete_after|backup_retention_days|lifecycle_rule|expiration)',
			flags: 'i',
			explanation:
				'Checks for the absence of retention-related keywords in backup or storage configuration.',
		},
		remediation:
			'Define a backup retention policy specifying the minimum and maximum retention periods. Align retention with your RPO, regulatory requirements, and disaster recovery plan. Use lifecycle rules to automatically expire old backups.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-005',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Cross-Region Backup',
		description:
			'Backups are not configured to be replicated to a secondary region. A regional outage could make primary backups inaccessible, violating recovery availability requirements.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'absence',
			value:
				'(copy_action|cross_region|replication_region|backup_vault.*region|geo.?redundant|secondary.?region)',
			flags: 'i',
			explanation:
				'Detects absence of cross-region or geo-redundant backup replication configuration.',
		},
		remediation:
			'Configure cross-region backup replication to at least one geographically separate region. Use provider features such as AWS Backup cross-region copy, Azure geo-redundant storage, or GCP multi-region buckets to ensure availability during regional failures.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-006',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Backup Integrity Verification',
		description:
			'No checksum, hash validation, or backup integrity verification process is defined. Without integrity checks, corrupted backups may go undetected until a recovery is attempted.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: '(checksum|md5|sha256|sha512|integrity.?check|verify.?backup|backup.?verif)',
			flags: 'i',
			explanation:
				'Checks for absence of backup integrity verification logic such as checksum or hash validation.',
		},
		remediation:
			'Implement backup integrity verification by computing and storing checksums (SHA-256 or stronger) at backup creation time and validating them prior to or after restoration. Automate verification as part of your backup workflow.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'a1-rec-007',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Point-in-Time Recovery',
		description:
			'Point-in-time recovery (PITR) is not enabled for the database. Without PITR, the system cannot restore data to an arbitrary past moment, significantly limiting recovery options after partial corruption or accidental deletion.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'regex',
			value:
				'(point.?in.?time|pitr|enable_pitr|point_in_time_recovery)\\s*[=:]\\s*["\']?(false|disabled|no|0)["\']?',
			flags: 'im',
			explanation:
				'Detects explicit disabling of point-in-time recovery in database or IaC configuration.',
		},
		remediation:
			'Enable point-in-time recovery (PITR) on all production databases. Configure transaction log backups at an interval consistent with your RPO. Test PITR restores periodically to validate recovery capability.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-008',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Database Replication Configuration',
		description:
			'Database replication is not configured. Without replication, a single database failure results in downtime until a restore completes, making recovery time objectives difficult to meet.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config', 'iac', 'kubernetes'],
		pattern: {
			type: 'absence',
			value:
				'(replication|replica|read.?replica|standby|synchronous_commit|replica_count|replicas)',
			flags: 'i',
			explanation:
				'Detects absence of database replication configuration keywords in infrastructure or config files.',
		},
		remediation:
			'Configure database replication with at least one replica in a separate availability zone. Use synchronous replication for critical data to prevent data loss. Validate that replicas are promoted automatically during failover.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-009',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Failover Configuration',
		description:
			'No automatic failover configuration is present. Systems that lack automated failover require manual intervention during outages, increasing recovery time and risk of prolonged unavailability.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config', 'iac', 'kubernetes'],
		pattern: {
			type: 'absence',
			value:
				'(failover|multi.?az|multi_az|automatic_failover|high.?availability|ha_enabled|failoverPriority)',
			flags: 'i',
			explanation:
				'Checks for absence of failover or high-availability configuration in infrastructure definitions.',
		},
		remediation:
			'Enable automatic failover using provider-managed features (e.g., RDS Multi-AZ, Azure SQL geo-failover groups, GCP Cloud SQL high availability). Test failover procedures regularly to confirm RTO compliance.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-010',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Health Check Endpoints',
		description:
			'Application health check endpoints are not defined. Without health checks, load balancers and orchestrators cannot detect unhealthy instances and route traffic away, resulting in degraded availability.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: '(\\/health|\\/healthz|\\/ping|\\/status|\\/ready|\\/live)',
			flags: 'i',
			explanation:
				'Detects absence of standard health check route definitions in application source or config.',
		},
		remediation:
			'Implement health check endpoints (e.g., GET /healthz, GET /ready) that return HTTP 200 when the application is healthy. Integrate these endpoints with your load balancer and orchestration platform health checks.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-rec-011',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Liveness Probes',
		description:
			'Kubernetes liveness probes are not configured on container definitions. Without liveness probes, Kubernetes cannot automatically restart containers that have entered a broken or deadlocked state.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'absence',
			value: 'livenessProbe',
			flags: '',
			explanation:
				'Checks that livenessProbe is defined in Kubernetes container specifications.',
		},
		remediation:
			'Add a livenessProbe to each container in your Kubernetes Deployment or StatefulSet. Configure an appropriate httpGet, tcpSocket, or exec probe with suitable initialDelaySeconds, periodSeconds, and failureThreshold values.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-rec-012',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Readiness Probes',
		description:
			'Kubernetes readiness probes are not configured. Without readiness probes, traffic is sent to containers before they are ready to serve requests, causing errors and degraded user experience during startup or recovery.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'absence',
			value: 'readinessProbe',
			flags: '',
			explanation:
				'Checks that readinessProbe is defined in Kubernetes container specifications.',
		},
		remediation:
			'Add a readinessProbe to each container in your Kubernetes workload definitions. Configure the probe to verify that the application can successfully handle traffic before Kubernetes routes requests to it.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-rec-013',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Restart Policy',
		description:
			'No restart policy is configured for containerized workloads. Without an explicit restart policy, failed containers may not be restarted automatically, resulting in avoidable downtime.',
		severity: 'medium',
		languages: ['any'],
		targets: ['kubernetes', 'dockerfile', 'config'],
		pattern: {
			type: 'absence',
			value: '(restartPolicy|restart_policy|restart:\\s*(always|on-failure|unless-stopped))',
			flags: 'i',
			explanation:
				'Detects absence of restart policy configuration in Kubernetes manifests or Docker Compose files.',
		},
		remediation:
			'Set an explicit restartPolicy in Kubernetes Pod specs (e.g., Always for Deployments) or a restart policy in Docker Compose (e.g., restart: always or restart: on-failure). Align the policy with your RTO and application criticality.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-rec-014',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Graceful Shutdown Handling',
		description:
			'Application code does not handle termination signals (SIGTERM/SIGINT) to perform a graceful shutdown. Without graceful shutdown, in-flight requests may be abruptly terminated, causing data inconsistency or failed transactions during rolling restarts or failovers.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'absence',
			value:
				'(SIGTERM|SIGINT|process\\.on\\s*\\(\\s*["\']SIGTERM|signal\\.Notify|Runtime\\.getRuntime.*addShutdownHook|graceful.?shutdown|gracefulStop)',
			flags: 'i',
			explanation:
				'Detects absence of signal handling or graceful shutdown logic in application source code.',
		},
		remediation:
			'Implement signal handlers for SIGTERM and SIGINT that stop accepting new requests, finish processing in-flight requests within a timeout, flush buffers, and close database connections before exiting. Configure terminationGracePeriodSeconds in Kubernetes to allow sufficient time.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-015',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Data Replication Strategy',
		description:
			'No data replication strategy is defined in the infrastructure or configuration. A single-site data store without replication is a single point of failure that can cause data loss and extended downtime.',
		severity: 'critical',
		languages: ['any'],
		targets: ['iac', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(replication_factor|replica_count|replication_group|storage_replication|redundancy|geo_redundant|zone_redundant)',
			flags: 'i',
			explanation:
				'Detects absence of data replication or redundancy configuration in infrastructure and config files.',
		},
		remediation:
			'Define an explicit data replication strategy specifying replication factor, replication topology (synchronous vs asynchronous), and target regions or availability zones. Validate replication lag metrics and set alerting thresholds.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'a1-rec-016',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No RPO/RTO Configuration',
		description:
			'Recovery Point Objective (RPO) and Recovery Time Objective (RTO) values are not documented or configured anywhere in the codebase or infrastructure definitions. Without defined RPO/RTO, backup and replication schedules cannot be validated against business requirements.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'absence',
			value: '(rpo|rto|recovery.?point.?objective|recovery.?time.?objective)',
			flags: 'i',
			explanation:
				'Checks for absence of RPO/RTO definitions in configuration and IaC files.',
		},
		remediation:
			'Document and enforce RPO and RTO values as configuration constants or infrastructure parameters. Align backup frequency, replication lag tolerances, and failover timeouts with the stated objectives. Include RPO/RTO assertions in recovery testing.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-017',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Recovery Testing Schedule',
		description:
			'No evidence of scheduled or automated recovery testing exists in CI/CD pipelines or configuration. Without periodic recovery tests, the actual recoverability of backups and failover procedures is unknown.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(recovery.?test|restore.?test|disaster.?recovery.?drill|dr.?drill|backup.?restore.?test)',
			flags: 'i',
			explanation:
				'Detects absence of recovery test or DR drill steps in CI/CD pipeline definitions or configuration files.',
		},
		remediation:
			'Schedule automated recovery tests in your CI/CD pipeline or as a periodic cron job. Tests should include backup restoration, failover initiation, and validation that the recovered system meets RPO and RTO targets. Document and review test results.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-018',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Rollback Automation',
		description:
			'Automated rollback mechanisms are absent from deployment pipelines. Without rollback automation, failed deployments require manual intervention, extending downtime and increasing the risk of human error during recovery.',
		severity: 'high',
		languages: ['any'],
		targets: ['cicd', 'kubernetes', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(rollback|roll.?back|undo.?deployment|revert.?deploy|maxSurge.*maxUnavailable|revisionHistoryLimit)',
			flags: 'i',
			explanation:
				'Checks for absence of rollback or deployment revision history configuration in CI/CD and Kubernetes manifests.',
		},
		remediation:
			'Implement automated rollback in your CI/CD pipeline triggered by deployment health check failures. In Kubernetes, configure revisionHistoryLimit and use kubectl rollout undo or a GitOps tool to enable rapid automated rollback.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-019',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Data Export Capability',
		description:
			'No data export functionality is implemented. Without data export capabilities, migrating data to a recovery environment or providing data portability during a disaster is significantly delayed.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value:
				'(export|dump|pg_dump|mysqldump|bcp|data.?export|exportData|exportToS3|to.?csv|to.?parquet)',
			flags: 'i',
			explanation:
				'Detects absence of data export or dump utility references in application source and config files.',
		},
		remediation:
			'Implement data export capabilities (e.g., database dump scripts, CSV/Parquet export APIs, or cloud-native export jobs). Automate periodic exports to durable storage and test import procedures as part of recovery drills.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://www.nist.gov/cyberframework',
			'https://www.iso.org/isoiec-27001-information-security.html',
		],
	},
	{
		id: 'a1-rec-020',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Disaster Recovery Runbook',
		description:
			'A disaster recovery runbook or playbook reference is absent from the repository. Without a documented runbook, recovery operations depend on tribal knowledge and are slower and more error-prone under stress.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'cicd'],
		pattern: {
			type: 'absence',
			value: '(runbook|playbook|disaster.?recovery|dr.?plan|incident.?response)',
			flags: 'i',
			explanation:
				'Checks for absence of runbook or disaster recovery plan references in configuration and CI/CD files.',
		},
		remediation:
			'Create and maintain a disaster recovery runbook that covers: detection and escalation, failover steps, data recovery procedures, communication plan, and post-incident review. Store the runbook in a version-controlled location accessible during an outage.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-021',
		criteria: 'A1.2',
		category: 'availability',
		title: 'Missing Recovery Point Objectives',
		description:
			'Recovery Point Objective (RPO) thresholds are not enforced or validated in backup or replication configuration. Without enforcement, actual data loss during recovery may exceed acceptable business tolerances.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac'],
		pattern: {
			type: 'regex',
			value:
				'(?:backup_interval|backup_frequency|replication_lag_threshold)\\s*[=:]\\s*(?:["\'])?(?:\\d+[dhms]?)',
			flags: 'im',
			explanation:
				'Identifies backup interval or replication lag configurations and flags where RPO enforcement values may be missing or unconstrained.',
		},
		remediation:
			'Define explicit RPO thresholds and enforce them by configuring backup intervals shorter than the RPO, setting replication lag alerts, and failing recovery tests that do not meet RPO targets. Document RPO values alongside backup configuration.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-rec-022',
		criteria: 'A1.2',
		category: 'availability',
		title: 'No Recovery Time Objective Monitoring',
		description:
			'Recovery Time Objective (RTO) monitoring is absent. Without monitoring and alerting on recovery duration metrics, it is impossible to detect when actual recovery times exceed agreed SLAs until a post-incident review.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac', 'cicd'],
		pattern: {
			type: 'absence',
			value:
				'(rto.?monitor|recovery.?time.?alert|failover.?duration|restore.?duration|rto.?alarm|rto.?metric)',
			flags: 'i',
			explanation:
				'Checks for absence of RTO monitoring, alerting, or metric collection configuration.',
		},
		remediation:
			'Instrument your recovery and failover processes to emit duration metrics. Configure alerting rules that fire when recovery time exceeds the defined RTO threshold. Include RTO measurement in automated recovery test reports and review trends over time.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
];
