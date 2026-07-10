/*--------------------------------------------------------------------------------------
 * Copyright 2026 Neural Inverse Inc. All rights reserved.
 * Licensed under the Business Source License 1.1. See LICENSE for more information.
 * Change Date: 2029-01-01 | Change License: GPL v2.0
 *--------------------------------------------------------------------------------------*/

import type { ISoc2Rule } from '../../types.js';

export const a1CapacityRules: ISoc2Rule[] = [
	{
		id: 'a1-cap-001',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing Auto-Scaling Configuration',
		description:
			'No auto-scaling policy is defined for compute resources. Without auto-scaling, services cannot respond to demand spikes, leading to availability failures. SOC2 A1.1 requires that capacity be managed to meet performance commitments.',
		severity: 'critical',
		languages: ['any'],
		targets: ['kubernetes', 'iac', 'config'],
		pattern: {
			type: 'absence',
			value: 'autoscaling|HorizontalPodAutoscaler|AutoScalingGroup|aws_autoscaling_group|google_compute_autoscaler|azurerm_monitor_autoscale_setting',
			flags: 'i',
			explanation:
				'Detects files that define deployments or instance groups but lack any reference to auto-scaling resources or policies.',
		},
		remediation:
			'Define a HorizontalPodAutoscaler for Kubernetes workloads or an AutoScaling Group for cloud VMs. Set minReplicas, maxReplicas, and CPU/memory utilization targets appropriate for your SLA. Validate scaling policies in a load-test environment before production.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-cap-002',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Resource Limits on Containers',
		description:
			'Container specifications do not define CPU or memory limits. An unbounded container can exhaust node resources, causing cascading failures across co-located services and violating availability commitments.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes', 'dockerfile'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: a1-cap-002
    patterns:
      - pattern: |
          containers:
            - name: ...
              image: ...
      - pattern-not: |
          resources:
            limits:
              ...
    message: Container definition is missing resource limits
    languages: [yaml]
    severity: WARNING`,
			explanation:
				'Matches Kubernetes container specifications that declare an image but omit the resources.limits block.',
		},
		remediation:
			'Add a resources.limits block to every container spec with cpu and memory values tuned to observed peak usage plus a safety margin. Use LimitRange objects to enforce default limits namespace-wide.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-cap-003',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing CPU and Memory Requests',
		description:
			'Kubernetes container definitions omit resource requests. Without requests, the scheduler cannot make informed placement decisions, leading to over-committed nodes and unpredictable performance degradation under load.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'regex',
			value: 'kind:\\s*(?:Deployment|StatefulSet|DaemonSet|Job|CronJob)[\\s\\S]*?containers:[\\s\\S]*?image:\\s*\\S+(?![\\s\\S]*?resources:\\s*\\n\\s*requests:)',
			flags: 'i',
			explanation:
				'Matches Kubernetes workload manifests where a container image is declared but no resources.requests block follows within the same spec.',
		},
		remediation:
			'Set resources.requests.cpu and resources.requests.memory for every container. Base values on p95 usage metrics collected over at least 72 hours. Pair with Vertical Pod Autoscaler in recommendation mode to continuously right-size requests.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-cap-004',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Horizontal Pod Autoscaler Defined',
		description:
			'Kubernetes deployments or stateful sets lack a HorizontalPodAutoscaler (HPA) resource. Without HPA, replica counts are static and the service cannot absorb traffic surges, directly threatening availability commitments.',
		severity: 'critical',
		languages: ['any'],
		targets: ['kubernetes'],
		pattern: {
			type: 'absence',
			value: 'kind:\\s*HorizontalPodAutoscaler',
			flags: 'i',
			explanation:
				'Checks that at least one HorizontalPodAutoscaler manifest exists in the Kubernetes configuration set being analysed.',
		},
		remediation:
			'Create a HorizontalPodAutoscaler targeting each production Deployment or StatefulSet. Configure scaleTargetRef, minReplicas, maxReplicas, and metrics (CPU, memory, or custom). Test scale-up and scale-down behavior with a realistic load profile.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-cap-005',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing Load Balancer Configuration',
		description:
			'No load balancer or traffic distribution mechanism is configured for the service. A single-endpoint deployment creates a single point of failure and cannot distribute load across replicas, violating availability requirements.',
		severity: 'critical',
		languages: ['any'],
		targets: ['kubernetes', 'iac', 'config'],
		pattern: {
			type: 'absence',
			value: 'LoadBalancer|Ingress|ingress|load_balancer|aws_lb|aws_alb|google_compute_forwarding_rule|azurerm_lb',
			flags: 'i',
			explanation:
				'Detects infrastructure or Kubernetes configuration files that lack any load balancer or ingress resource definition.',
		},
		remediation:
			'Expose services through a Kubernetes Service of type LoadBalancer or an Ingress controller. For cloud deployments, provision an Application Load Balancer with health checks targeting all instances. Enable cross-zone load balancing and configure stickiness only when session state requires it.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-cap-006',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Database Connection Pooling',
		description:
			'Application code opens database connections without a pooling mechanism. Each request that creates a raw connection consumes a database server slot; under load this exhausts the server connection limit and causes connection-refused errors.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: 'new\\s+(?:pg\\.Client|mysql\\.createConnection|sqlite3\\.Database|MongoClient|pymysql\\.connect|psycopg2\\.connect|cx_Oracle\\.connect|java\\.sql\\.DriverManager\\.getConnection|sql\\.Open)\\s*\\(',
			flags: 'i',
			explanation:
				'Matches direct database connection instantiation calls that bypass a connection pool, such as new pg.Client(), mysql.createConnection(), or psycopg2.connect().',
		},
		remediation:
			'Replace direct connection calls with a pooling library (pg-pool, HikariCP, pgbouncer, SQLAlchemy pool, database/sql in Go). Configure pool.min, pool.max, and pool.idleTimeoutMillis based on expected concurrency. Monitor pool wait-time and pool-exhaustion metrics.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'a1-cap-007',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing Database Connection Limits',
		description:
			'Database configuration does not specify a maximum number of connections. Without an explicit upper bound, a misbehaving client can open thousands of connections, starving other services and causing database-wide unavailability.',
		severity: 'high',
		languages: ['any'],
		targets: ['config', 'iac', 'source'],
		pattern: {
			type: 'absence',
			value: 'max(?:_connections|Connections|ConnectionPoolSize|PoolSize|pool_size|connectionLimit)\\s*[=:]\\s*\\d+',
			flags: 'i',
			explanation:
				'Checks that a database connection pool or server configuration declares an explicit maximum connection count.',
		},
		remediation:
			'Set max_connections in PostgreSQL/MySQL server config and enforce matching pool.max in every application client. Use PgBouncer or ProxySQL as a connection multiplexer to protect the database from pool proliferation across many application pods.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-cap-008',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Queue Depth Monitoring',
		description:
			'Message queue or task queue configurations lack depth or backlog alerting. An unbounded growing queue signals that consumers are not keeping pace with producers; left undetected this delays critical workloads and can exhaust broker storage.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'iac', 'source'],
		pattern: {
			type: 'absence',
			value: 'queue(?:_depth|Depth|_length|Length|_size|Size|_lag|Lag)|ApproximateNumberOfMessages|rabbitmq_queue_messages|kafka_consumer_lag',
			flags: 'i',
			explanation:
				'Detects the absence of queue depth or consumer-lag metric references in monitoring, alerting, or application configuration files.',
		},
		remediation:
			'Instrument CloudWatch, Prometheus, or Datadog to track queue depth and consumer lag. Create alerts when depth exceeds a threshold corresponding to your acceptable processing latency. Implement auto-scaling of consumers based on queue depth metrics.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-cap-009',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing Capacity Planning Metrics',
		description:
			'No capacity planning metrics such as CPU utilization trends, memory growth, or storage fill-rate are captured or exported. Without trend data it is impossible to proactively provision resources before saturation occurs.',
		severity: 'medium',
		languages: ['any'],
		targets: ['config', 'iac', 'cicd'],
		pattern: {
			type: 'absence',
			value: 'capacity|utilization|saturation|forecast|trend|headroom|resource_usage',
			flags: 'i',
			explanation:
				'Checks that monitoring or observability configuration references capacity planning terms such as utilization, saturation, or forecast.',
		},
		remediation:
			'Collect and retain CPU, memory, disk, and network utilization metrics with at least 90-day retention. Build capacity dashboards that project linear and exponential growth trends. Review capacity forecasts in a monthly operations review aligned to your SOC2 monitoring procedures.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-cap-010',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Traffic Shaping or Rate Limiting at the Network Layer',
		description:
			'Infrastructure configuration does not implement traffic shaping, QoS policies, or ingress rate limiting. Without network-layer controls, a single abusive client or traffic spike can saturate the network interface and degrade service for all users.',
		severity: 'high',
		languages: ['any'],
		targets: ['kubernetes', 'iac', 'config'],
		pattern: {
			type: 'absence',
			value: 'trafficPolicy|traffic_shaping|bandwidth|qos|ingress\\.kubernetes\\.io\\/limit|nginx\\.ingress\\.kubernetes\\.io\\/limit-rps|nginx\\.ingress\\.kubernetes\\.io\\/limit-connections',
			flags: 'i',
			explanation:
				'Checks for the absence of traffic shaping annotations, QoS configurations, or ingress rate limit directives in Kubernetes or infrastructure files.',
		},
		remediation:
			'Add nginx.ingress.kubernetes.io/limit-rps and limit-connections annotations to Ingress objects. For Istio service meshes, define a VirtualService with traffic shaping. For cloud load balancers, configure WAF rate-based rules to protect against burst traffic.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-cap-011',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing CDN Configuration',
		description:
			'Static assets and cacheable API responses are served directly from origin servers with no Content Delivery Network in front. Without a CDN, origin servers bear the full cost of geographic distribution and static asset delivery, reducing capacity for dynamic workloads.',
		severity: 'medium',
		languages: ['any'],
		targets: ['iac', 'config'],
		pattern: {
			type: 'absence',
			value: 'cdn|CloudFront|cloudfront|fastly|akamai|cloudflare|azure_cdn|google_cdn|aws_cloudfront_distribution',
			flags: 'i',
			explanation:
				'Detects the absence of CDN or content delivery resource declarations in infrastructure-as-code or application configuration files.',
		},
		remediation:
			'Provision a CDN distribution (Amazon CloudFront, Cloudflare, Fastly) in front of static asset buckets and public API endpoints. Configure appropriate TTLs, cache-control headers, and cache invalidation pipelines tied to deployment events.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-cap-012',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Caching Layer Configured',
		description:
			'Application or infrastructure configuration shows no in-process or distributed cache (Redis, Memcached, Varnish, etc.). Serving every request from the database amplifies read load, constrains throughput, and creates a single point of capacity failure at the data tier.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'any'],
		targets: ['source', 'config', 'iac'],
		pattern: {
			type: 'absence',
			value: 'redis|memcached|cache|Cache|caching|lru-cache|node-cache|django\\.core\\.cache|spring\\.cache|go-cache|groupcache',
			flags: 'i',
			explanation:
				'Checks that caching library imports, cache client instantiations, or caching infrastructure resources are present in the codebase or configuration.',
		},
		remediation:
			'Introduce a distributed cache (Redis or Memcached) for session data, hot database query results, and rendered page fragments. Define cache eviction policies and TTLs aligned with data freshness requirements. Monitor cache hit ratio; a ratio below 80% warrants tuning.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'a1-cap-013',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing Database Index Optimization Hints',
		description:
			'Database migration files or schema definitions contain tables without indexes on foreign keys or high-cardinality filter columns. Unindexed queries perform full-table scans that grow linearly with data volume, consuming CPU and memory well beyond planned capacity.',
		severity: 'medium',
		languages: ['any'],
		targets: ['migration', 'schema'],
		pattern: {
			type: 'regex',
			value: 'CREATE\\s+TABLE\\s+\\w+[^;]*;(?![\\s\\S]*?CREATE\\s+(?:UNIQUE\\s+)?INDEX\\s+\\w+\\s+ON\\s+\\w+)',
			flags: 'i',
			explanation:
				'Matches CREATE TABLE statements that are not followed by any CREATE INDEX statement targeting the same table, indicating potential missing index coverage.',
		},
		remediation:
			'Audit query patterns with EXPLAIN ANALYZE (PostgreSQL) or EXPLAIN FORMAT=JSON (MySQL). Add indexes on all foreign key columns, frequently filtered columns, and sorting columns. Use partial indexes for large tables with selective predicates. Review indexes quarterly as query patterns evolve.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'a1-cap-014',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Query Timeout Configuration',
		description:
			'Database client or ORM configuration does not set statement or query timeouts. A runaway or slow query can hold locks and consume database CPU indefinitely, blocking other requests and causing cascading latency spikes across dependent services.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: 'statement_timeout|query_timeout|queryTimeout|statementTimeout|lock_timeout|connect_timeout|socket_timeout|command_timeout',
			flags: 'i',
			explanation:
				'Detects the absence of timeout configuration parameters in database client configurations, ORM settings, or connection string options.',
		},
		remediation:
			'Set statement_timeout and lock_timeout in PostgreSQL connection parameters or at the session level. For MySQL, configure wait_timeout and max_execution_time. In ORMs (TypeORM, Sequelize, SQLAlchemy), set the queryTimeout or pool connectionTimeout. Apply request-scoped timeouts that are shorter than the upstream HTTP timeout.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'a1-cap-015',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing Bulk Operation Size Limits',
		description:
			'API endpoints or service methods that accept bulk or batch payloads do not enforce a maximum item count or byte size. An oversized bulk request consumes disproportionate CPU, memory, and database resources, degrading service for concurrent users.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '(?:bulk|batch|insertMany|createMany|updateMany|deleteMany|batchWrite|bulkWrite)\\s*\\([^)]*\\)(?![\\s\\S]{0,300}(?:limit|maxItems|maxBatch|MAX_BATCH|chunkSize|chunk_size|pageSize|MAX_SIZE))',
			flags: 'i',
			explanation:
				'Matches bulk or batch operation calls that are not followed within 300 characters by a size-limiting variable or constant, suggesting unbounded batch processing.',
		},
		remediation:
			'Enforce a configurable MAX_BATCH_SIZE constant at the API validation layer. Return HTTP 400 when the payload exceeds the limit. Process large batches in paginated chunks internally. Document the batch size limit in API contracts and alert when clients approach the boundary.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'a1-cap-016',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Pagination on List Endpoints',
		description:
			'API endpoints that return collections do not implement pagination. A client requesting an unbounded list can trigger a full-table scan and return megabytes or gigabytes of data, exhausting database, application, and network resources simultaneously.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source'],
		pattern: {
			type: 'semgrep',
			value: `rules:
  - id: a1-cap-016
    patterns:
      - pattern-either:
          - pattern: $ROUTER.get($PATH, ..., $HANDLER)
          - pattern: app.get($PATH, ..., $HANDLER)
      - pattern-not-regex: "(?:limit|offset|page|cursor|per_page|pageSize|take|skip)"
    message: List endpoint may be missing pagination controls
    languages: [javascript, typescript]
    severity: WARNING`,
			explanation:
				'Matches HTTP GET route handlers whose path or handler source does not reference common pagination parameters such as limit, offset, page, cursor, or take.',
		},
		remediation:
			'Implement cursor-based or offset-based pagination on all collection endpoints. Enforce a maximum page size (e.g., 100 items) and default page size (e.g., 20 items). Return pagination metadata (next cursor, total count) in response envelopes. Reject requests where limit exceeds the maximum.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'a1-cap-017',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing Per-User Rate Limiting',
		description:
			'The application does not enforce per-user or per-API-key rate limits. A single authenticated user can issue unlimited requests, monopolising server capacity and degrading service for all other users in violation of availability commitments.',
		severity: 'critical',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: 'rateLimit|rate_limit|RateLimit|throttle|Throttle|express-rate-limit|django-ratelimit|rack-throttle|golang\\.org\\/x\\/time\\/rate|rate\\.NewLimiter|bucket4j|resilience4j\\.ratelimiter',
			flags: 'i',
			explanation:
				'Detects the absence of rate-limiting middleware imports, annotations, or client instantiations within application source and configuration files.',
		},
		remediation:
			'Apply per-user rate limiting middleware at the API gateway or application layer. Use a token-bucket or sliding-window algorithm stored in Redis for distributed enforcement. Define separate tiers (e.g., 100 req/min for free, 1000 req/min for paid) and return HTTP 429 with Retry-After headers when limits are exceeded.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://owasp.org/www-project-top-ten/',
		],
	},
	{
		id: 'a1-cap-018',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Circuit Breaker Configuration',
		description:
			'Service-to-service calls do not use circuit breaker patterns. When a downstream dependency degrades, repeated calls pile up, exhaust thread pools and connection pools, and cause the calling service to fail as well, creating a cascading outage.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'],
		targets: ['source', 'config'],
		pattern: {
			type: 'absence',
			value: 'circuit.?breaker|CircuitBreaker|opossum|hystrix|Hystrix|resilience4j|pybreaker|gobreaker|polly|Polly|istio.*outlierDetection',
			flags: 'i',
			explanation:
				'Checks that circuit breaker library imports, annotations, or Istio outlierDetection policies are referenced in the service source or configuration.',
		},
		remediation:
			'Wrap all outbound HTTP and RPC calls with a circuit breaker (Opossum for Node.js, Resilience4j for Java, pybreaker for Python, gobreaker for Go). Configure failure threshold, timeout, and half-open probe interval. Expose circuit state as a metric and alert when a circuit is open.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-cap-019',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing Backpressure Handling',
		description:
			'Asynchronous processing pipelines or streaming code does not implement backpressure signals. Producers that outrun consumers cause in-memory buffer growth, ultimately leading to out-of-memory crashes or message loss that disrupts service availability.',
		severity: 'high',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'rust'],
		targets: ['source'],
		pattern: {
			type: 'regex',
			value: '\\.pipe\\s*\\(|new\\s+(?:Transform|Readable|Writable|PassThrough|Subject|BehaviorSubject)\\s*\\(|rx\\.Observable|asyncio\\.Queue\\s*\\((?![^)]*maxsize)',
			flags: 'i',
			explanation:
				'Matches stream pipe chains, RxJS subjects, or asyncio queues that may not be configured with backpressure controls like highWaterMark or bounded queue sizes.',
		},
		remediation:
			'Set highWaterMark on Node.js Readable/Writable streams and call stream.pause()/stream.resume() to honour backpressure signals. For RxJS, use operators like bufferCount, throttleTime, or concatMap with bounded inner observables. For asyncio.Queue, set maxsize. For Kafka consumers, commit offsets only after successful processing.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-cap-020',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Memory Leak Detection',
		description:
			'Application code or container configuration includes no memory profiling, heap snapshot tooling, or leak-detection instrumentation. Undetected memory leaks cause gradual performance degradation and eventually OOM-kills that disrupt service availability.',
		severity: 'medium',
		languages: ['typescript', 'javascript', 'python', 'java', 'go', 'ruby', 'csharp'],
		targets: ['source', 'config', 'dockerfile'],
		pattern: {
			type: 'absence',
			value: 'memwatch|heapdump|clinic|0x|valgrind|memory_profiler|tracemalloc|jmap|pprof|runtime/pprof|dotMemory|BenchmarkDotNet|process\\.memoryUsage',
			flags: 'i',
			explanation:
				'Detects the absence of memory profiling tool imports, heap dump utilities, or memory usage instrumentation in application source and configuration.',
		},
		remediation:
			'Integrate a memory monitoring library (memwatch-next for Node.js, tracemalloc for Python, pprof for Go). Export process.memoryUsage() (Node.js) or equivalent as a Prometheus gauge. Create an alert when heap usage grows more than 20% over a rolling 1-hour window. Run automated heap profiling in staging under load.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
		],
	},
	{
		id: 'a1-cap-021',
		criteria: 'A1.1',
		category: 'availability',
		title: 'Missing File Descriptor Limits',
		description:
			'Container or process configuration does not set ulimit nofile (open file descriptor) limits. Applications that open many sockets, files, or pipes without limits can exhaust OS file descriptors, causing EMFILE errors that prevent new connections and crash the process.',
		severity: 'medium',
		languages: ['any'],
		targets: ['dockerfile', 'kubernetes', 'config', 'iac'],
		pattern: {
			type: 'absence',
			value: 'ulimit|nofile|RLIMIT_NOFILE|fs\\.file-max|LimitNOFILE|ulimits|allowPrivilegeEscalation.*false[\\s\\S]*?nofile|security.*context.*nofile',
			flags: 'i',
			explanation:
				'Checks that Dockerfile, Kubernetes securityContext, systemd unit, or OS configuration specifies an explicit file descriptor (nofile) limit.',
		},
		remediation:
			'Add ulimits.nofile.soft and ulimits.nofile.hard to Docker Compose or Dockerfile. In Kubernetes, set container securityContext with appropriate limits or use a DaemonSet to configure node-level sysctl fs.file-max. For systemd services, set LimitNOFILE in the unit file. Start with 65535 and tune upward based on observed peak descriptor usage.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
	{
		id: 'a1-cap-022',
		criteria: 'A1.1',
		category: 'availability',
		title: 'No Disk Space Monitoring',
		description:
			'Infrastructure or application configuration does not include disk utilisation monitoring or alerting. When disk space is exhausted, write operations fail, databases crash, log pipelines stall, and application processes may terminate, causing full service unavailability.',
		severity: 'critical',
		languages: ['any'],
		targets: ['config', 'iac', 'cicd'],
		pattern: {
			type: 'absence',
			value: 'disk(?:_space|_usage|Space|Usage|Free|free|Available|available)|node_filesystem_avail_bytes|disk\\.used_percent|CloudWatch.*disk|Datadog.*disk|df\\s+-h',
			flags: 'i',
			explanation:
				'Detects the absence of disk space or filesystem utilisation metric references in monitoring configuration, alerting rules, or infrastructure definitions.',
		},
		remediation:
			'Deploy node_exporter (Prometheus) or CloudWatch Agent to collect node_filesystem_avail_bytes. Create paging alerts at 80% full and critical alerts at 90% full. Automate log rotation with logrotate and set retention policies. For databases, monitor tablespace usage and implement data archiving to object storage.',
		references: [
			'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria',
			'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
			'https://www.nist.gov/cyberframework',
			'https://www.cisecurity.org/cis-benchmarks',
		],
	},
];
