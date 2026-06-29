<?php

namespace App\Services;

use App\Models\Project;
use Cron\CronExpression;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class RecordService
{
    /**
     * Get aggregated stats for various record types.
     */
    public function getQuickStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $types = ['request', 'exception', 'query', 'queued-job', 'job-attempt', 'scheduled-task', 'cache-event', 'log', 'mail', 'notification', 'outgoing-request'];
        $stats = [];

        foreach ($types as $type) {
            $key = str_replace('-', '_', $type).'s';
            $count = $project->records()->ofType($type)->forPeriod($period, $from, $to)->count();

            if (isset($stats[$key])) {
                $stats[$key] += $count;
            } else {
                $stats[$key] = $count;
            }
        }

        // Aggregate jobs
        $stats['jobs'] = ($stats['queued_jobs'] ?? 0) + ($stats['job_attempts'] ?? 0);

        return $stats;
    }

    /**
     * Aggregate Request Data
     */
    public function getRequestStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null, string $sort = 'total', string $direction = 'desc'): array
    {
        $allowedSorts = ['method', 'path', 'total', 'ok_count', 'client_error_count', 'server_error_count', 'avg_duration', 'p95_duration'];
        $sort = in_array($sort, $allowedSorts) ? $sort : 'total';
        $direction = $direction === 'asc' ? 'asc' : 'desc';
        $statusCode = $this->jsonNumeric('status_code');
        $duration = $this->jsonNumeric('duration');
        $method = "COALESCE({$this->jsonText('method')}, 'GET')";
        $path = "COALESCE({$this->jsonText('route_path')}, '/')";

        $overview = $project->records()
            ->ofType('request')
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("SUM(CASE WHEN {$statusCode} BETWEEN 100 AND 399 THEN 1 ELSE 0 END) as ok"),
                DB::raw("SUM(CASE WHEN {$statusCode} BETWEEN 400 AND 499 THEN 1 ELSE 0 END) as client_error"),
                DB::raw("SUM(CASE WHEN {$statusCode} >= 500 THEN 1 ELSE 0 END) as server_error"),
                DB::raw("AVG({$duration}) as avg_duration"),
                DB::raw("MAX({$duration}) as max_duration"),
                DB::raw("MIN({$duration}) as min_duration"),
            ])->first();

        return [
            'requests' => $project->records()
                ->ofType('request')
                ->forPeriod($period, $from, $to)
                ->select([
                    // method/path are functionally determined by fingerprint
                    // (fingerprint = md5(method.route_path)), so grouping by the
                    // real, indexed fingerprint column alone yields identical
                    // groups while letting the (project_id, type, fingerprint)
                    // index do the work instead of grouping on JSON expressions.
                    DB::raw("MIN({$method}) as method"),
                    DB::raw("MIN({$path}) as path"),
                    'fingerprint as hash',
                    DB::raw('COUNT(*) as total'),
                    DB::raw("SUM(CASE WHEN {$statusCode} BETWEEN 100 AND 399 THEN 1 ELSE 0 END) as ok_count"),
                    DB::raw("SUM(CASE WHEN {$statusCode} BETWEEN 400 AND 499 THEN 1 ELSE 0 END) as client_error_count"),
                    DB::raw("SUM(CASE WHEN {$statusCode} >= 500 THEN 1 ELSE 0 END) as server_error_count"),
                    DB::raw("AVG({$duration}) as avg_duration"),
                    DB::raw("MAX({$duration}) as p95_duration"),
                ])
                ->groupBy('fingerprint')
                ->orderBy($sort, $direction)
                ->paginate(20)->withQueryString(),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'request', $period, $from, $to),
            'overview' => [
                'ok' => (int) ($overview->ok ?? 0),
                'client_error' => (int) ($overview->client_error ?? 0),
                'server_error' => (int) ($overview->server_error ?? 0),
                'avg_duration' => round($overview->avg_duration ?? 0, 2),
                'max_duration' => round($overview->max_duration ?? 0, 2),
                'min_duration' => round($overview->min_duration ?? 0, 2),
            ],
            'sort' => $sort,
            'direction' => $direction,
        ];
    }

    /**
     * Get comprehensive dashboard metrics.
     */
    public function getDashboardStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $records = $project->records()->forPeriod($period, $from, $to);
        $statusCode = $this->jsonNumeric('status_code');
        $duration = $this->jsonNumeric('duration');
        $status = $this->jsonText('status');
        $user = $this->jsonValue('user');
        $userDistinct = $this->jsonDistinct('user');
        $userId = "COALESCE({$this->jsonText('user.id')}, {$this->jsonText('user')}, 'Anonymous')";
        $userIdentifier = "COALESCE({$this->jsonText('user.name')}, {$this->jsonText('user_name')}, {$this->jsonText('user')}, 'Anonymous')";
        $userEmail = "COALESCE({$this->jsonText('user.email')}, {$this->jsonText('user_email')}, '')";

        $requestStats = (clone $records)->ofType('request')
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("SUM(CASE WHEN {$statusCode} BETWEEN 100 AND 399 THEN 1 ELSE 0 END) as ok"),
                DB::raw("SUM(CASE WHEN {$statusCode} BETWEEN 400 AND 499 THEN 1 ELSE 0 END) as client_error"),
                DB::raw("SUM(CASE WHEN {$statusCode} >= 500 THEN 1 ELSE 0 END) as server_error"),
                DB::raw("AVG({$duration}) as avg_duration"),
                DB::raw("MAX({$duration}) as max_duration"),
                DB::raw("MIN({$duration}) as min_duration"),
            ])->first();

        $jobStats = (clone $records)->whereIn('type', ['job-attempt', 'queued-job'])
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("SUM(CASE WHEN {$status} = 'processed' THEN 1 ELSE 0 END) as processed"),
                DB::raw("SUM(CASE WHEN {$status} = 'failed' THEN 1 ELSE 0 END) as failed"),
                DB::raw("SUM(CASE WHEN {$status} = 'released' THEN 1 ELSE 0 END) as released"),
                DB::raw("AVG({$duration}) as avg_duration"),
                DB::raw("MAX({$duration}) as p95_duration"),
            ])->first();

        $impactedUsers = (clone $records)->ofType('exception')
            ->whereRaw("{$user} IS NOT NULL")
            ->select([
                DB::raw("{$userId} as user_id"),
                DB::raw("{$userIdentifier} as user_identifier"),
                DB::raw("{$userEmail} as user_email"),
                DB::raw('COUNT(*) as error_count'),
                DB::raw('MAX(created_at) as last_seen'),
            ])
            ->groupBy('user_id', 'user_identifier', 'user_email')
            ->orderBy('error_count', 'desc')
            ->limit(5)
            ->get();

        $activeUsers = (clone $records)->ofType('request')
            ->whereRaw("{$user} IS NOT NULL")
            ->select([
                DB::raw("{$userId} as user_id"),
                DB::raw("{$userIdentifier} as user_identifier"),
                DB::raw("{$userEmail} as user_email"),
                DB::raw('COUNT(*) as request_count'),
            ])
            ->groupBy('user_id', 'user_identifier', 'user_email')
            ->orderBy('request_count', 'desc')
            ->limit(5)
            ->get();

        $this->enrichUserRows($project, $impactedUsers);
        $this->enrichUserRows($project, $activeUsers);

        return [
            'total_requests' => $requestStats->total ?? 0,
            'request_breakdown' => [
                'ok' => (int) ($requestStats->ok ?? 0),
                'client_error' => (int) ($requestStats->client_error ?? 0),
                'server_error' => (int) ($requestStats->server_error ?? 0),
            ],
            'duration_stats' => [
                'avg' => round($requestStats->avg_duration ?? 0, 2),
                'max' => round($requestStats->max_duration ?? 0, 2),
                'min' => round($requestStats->min_duration ?? 0, 2),
            ],
            'total_exceptions' => $project->records()->ofType('exception')->forPeriod($period, $from, $to)->count(),
            'recent_issues' => $project->issues()->where('status', 'open')->latest('last_seen_at')->limit(5)->get(),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'request', $period, $from, $to),
            'job_stats' => [
                'total' => $jobStats->total ?? 0,
                'processed' => (int) ($jobStats->processed ?? 0),
                'failed' => (int) ($jobStats->failed ?? 0),
                'released' => (int) ($jobStats->released ?? 0),
                'avg_duration' => round(($jobStats->avg_duration ?? 0) / 1000, 2),
                'p95_duration' => round(($jobStats->p95_duration ?? 0) / 1000, 2),
            ],
            'impacted_users' => $impactedUsers,
            'active_users' => $activeUsers,
            'auth_users_count' => (clone $records)->ofType('request')->whereRaw("{$user} IS NOT NULL")->distinct(DB::raw($userDistinct))->count(),
            'guest_users_count' => (clone $records)->ofType('request')->whereRaw("{$user} IS NULL")->count(),
            'period' => $period,
            'uptime_status' => [
                'current' => $project->last_uptime_status ?? 'unknown',
                'last_check' => $project->last_uptime_check_at ? $project->last_uptime_check_at->toIso8601String() : null,
                'url' => $project->url,
            ],
        ];
    }

    /**
     * Aggregate User Data
     */
    public function getUserStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $records = $project->records()->forPeriod($period, $from, $to);
        $user = $this->jsonValue('user');
        $userDistinct = $this->jsonDistinct('user');
        $statusCode = $this->jsonNumeric('status_code');
        $userHash = "MD5(COALESCE({$this->jsonText('user')}, 'Anonymous'))";

        $authCount = (clone $records)->ofType('request')->whereRaw("{$user} IS NOT NULL")->distinct(DB::raw($userDistinct))->count();
        $guestCount = (clone $records)->ofType('request')->whereRaw("{$user} IS NULL")->count();
        $totalAuthRequests = (clone $records)->ofType('request')->whereRaw("{$user} IS NOT NULL")->count();

        return [
            'users' => $this->enrichUserPaginator($project, $project->records()
                ->whereRaw("{$user} IS NOT NULL")
                ->forPeriod($period, $from, $to)
                ->select([
                    DB::raw("COALESCE(
                        {$this->jsonText('user.name')},
                        {$this->jsonText('user_name')},
                        {$this->jsonText('user')},
                        'Anonymous'
                    ) as user_name"),
                    DB::raw("COALESCE(
                        {$this->jsonText('user.email')},
                        {$this->jsonText('user_email')},
                        ''
                    ) as user_email"),
                    DB::raw("COALESCE(
                        {$this->jsonText('user.id')},
                        {$this->jsonText('user')},
                        'Anonymous'
                    ) as user_id"),
                    DB::raw("{$userHash} as hash"),
                    DB::raw('COUNT(*) as total_requests'),
                    DB::raw('MAX(created_at) as last_seen'),
                    DB::raw("SUM(CASE WHEN {$statusCode} >= 400 THEN 1 ELSE 0 END) as error_count"),
                    DB::raw("SUM(CASE WHEN type = 'exception' THEN 1 ELSE 0 END) as exception_count"),
                ])
                ->groupBy('user_name', 'user_email', 'user_id', 'hash')
                ->orderBy('last_seen', 'desc')
                ->paginate(20)->withQueryString()),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'request', $period, $from, $to),
            'overview' => [
                'auth_users' => $authCount,
                'guest_requests' => $guestCount,
                'auth_requests' => $totalAuthRequests,
            ],
        ];
    }

    /**
     * Aggregate Job Data
     */
    public function getJobStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $types = ['job-attempt', 'queued-job'];
        $status = $this->jsonText('status');
        $duration = $this->jsonNumeric('duration');

        $overview = $project->records()
            ->whereIn('type', $types)
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("SUM(CASE WHEN {$status} = 'processed' THEN 1 ELSE 0 END) as processed"),
                DB::raw("SUM(CASE WHEN {$status} = 'failed' THEN 1 ELSE 0 END) as failed"),
                DB::raw("AVG({$duration}) as avg_duration"),
                DB::raw("MAX({$duration}) as max_duration"),
            ])->first();

        return [
            'jobs' => $project->records()
                ->whereIn('type', $types)
                ->forPeriod($period, $from, $to)
                ->select([
                    // job_class is a display label for the fingerprint group
                    // (fingerprint = md5(job/name/job_class)); group by the
                    // indexed fingerprint instead of the JSON COALESCE.
                    DB::raw("MIN(COALESCE(
                        {$this->jsonText('name')},
                        {$this->jsonText('job')},
                        {$this->jsonText('job_class')},
                        {$this->jsonText('payload.name')},
                        {$this->jsonText('payload.displayName')},
                        {$this->jsonText('data.commandName')},
                        'Unknown Job'
                    )) as job_class"),
                    'fingerprint as hash',
                    DB::raw('COUNT(*) as total'),
                    DB::raw("SUM(CASE WHEN {$status} = 'processed' THEN 1 ELSE 0 END) as processed_count"),
                    DB::raw("SUM(CASE WHEN {$status} = 'failed' THEN 1 ELSE 0 END) as failed_count"),
                    DB::raw("AVG({$duration}) as avg_duration"),
                    DB::raw("MAX({$duration}) as p95_duration"),
                ])
                ->groupBy('fingerprint')
                ->orderBy('total', 'desc')
                ->paginate(20)->withQueryString(),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'job-attempt', $period, $from, $to),
            'overview' => [
                'total' => (int) ($overview->total ?? 0),
                'processed' => (int) ($overview->processed ?? 0),
                'failed' => (int) ($overview->failed ?? 0),
                'avg_duration' => round($overview->avg_duration ?? 0, 2),
                'max_duration' => round($overview->max_duration ?? 0, 2),
            ],
        ];
    }

    /**
     * Exceptions Aggregation
     */
    public function getExceptionStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $user = $this->jsonValue('user');
        $userDistinct = $this->jsonDistinct('user');

        $overview = $project->records()
            ->ofType('exception')
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw('COUNT(DISTINCT fingerprint) as unique_types'),
            ])->first();

        return [
            'exceptions' => $project->records()
                ->ofType('exception')
                ->forPeriod($period, $from, $to)
                ->select([
                    'fingerprint as hash',
                    // class/message are the fingerprint inputs (fingerprint =
                    // md5(class.message)), so grouping by the indexed fingerprint
                    // alone is equivalent and avoids grouping on JSON expressions.
                    DB::raw("MIN({$this->jsonText('class')}) as class"),
                    DB::raw("MIN({$this->jsonText('message')}) as message"),
                    DB::raw('COUNT(*) as total_count'),
                    DB::raw("COUNT(DISTINCT {$userDistinct}) as user_count"),
                    DB::raw('MAX(created_at) as last_seen'),
                ])
                ->groupBy('fingerprint')
                ->orderBy('last_seen', 'desc')
                ->paginate(20)->withQueryString(),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'exception', $period, $from, $to),
            'overview' => [
                'total' => (int) ($overview->total ?? 0),
                'unique' => (int) ($overview->unique_types ?? 0),
            ],
        ];
    }

    /**
     * Commands Aggregation
     */
    public function getCommandStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $exitCode = $this->jsonNumeric('exit_code');
        $duration = $this->jsonNumeric('duration');

        $overview = $project->records()
            ->ofType('command')
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("SUM(CASE WHEN {$exitCode} = 0 THEN 1 ELSE 0 END) as success"),
                DB::raw("SUM(CASE WHEN {$exitCode} != 0 THEN 1 ELSE 0 END) as failed"),
                DB::raw("AVG({$duration}) as avg_duration"),
            ])->first();

        return [
            'commands' => $project->records()
                ->ofType('command')
                ->forPeriod($period, $from, $to)
                ->select([
                    DB::raw("COALESCE(
                        {$this->jsonText('command')},
                        {$this->jsonText('name')},
                        {$this->jsonText('payload.command')},
                        {$this->jsonText('data.command')},
                        'Unknown Command'
                    ) as command_name"),
                    'fingerprint as hash',
                    DB::raw('COUNT(*) as total'),
                    DB::raw("SUM(CASE WHEN {$exitCode} = 0 THEN 1 ELSE 0 END) as success_count"),
                    DB::raw("SUM(CASE WHEN {$exitCode} != 0 THEN 1 ELSE 0 END) as failed_count"),
                    DB::raw("AVG({$duration}) as avg_duration"),
                    DB::raw("MAX({$duration}) as p95_duration"),
                ])
                ->groupBy('command_name', 'fingerprint')
                ->paginate(20)->withQueryString(),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'command', $period, $from, $to),
            'overview' => [
                'total' => (int) ($overview->total ?? 0),
                'success' => (int) ($overview->success ?? 0),
                'failed' => (int) ($overview->failed ?? 0),
                'avg_duration' => round($overview->avg_duration ?? 0, 2),
            ],
        ];
    }

    /**
     * Scheduled Tasks Aggregation
     */
    public function getScheduledTaskStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $exitCode = $this->jsonNumeric('exit_code');
        $exitCodeValue = $this->jsonValue('exit_code');
        $duration = $this->jsonNumeric('duration');
        $status = $this->jsonText('status');

        $overview = $project->records()
            ->ofType('scheduled-task')
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("SUM(CASE WHEN {$exitCode} = 0 THEN 1 ELSE 0 END) as success"),
                DB::raw("SUM(CASE WHEN {$exitCode} != 0 THEN 1 ELSE 0 END) as failed"),
                DB::raw("AVG({$duration}) as avg_duration"),
            ])->first();

        return [
            'tasks' => $project->records()
                ->ofType('scheduled-task')
                ->forPeriod($period, $from, $to)
                ->select([
                    DB::raw("COALESCE(
                        {$this->jsonText('command')},
                        {$this->jsonText('name')},
                        {$this->jsonText('payload.command')},
                        'Unknown Task'
                    ) as command"),
                    DB::raw("COALESCE(
                        {$this->jsonText('cron')},
                        {$this->jsonText('expression')},
                        {$this->jsonText('schedule')}
                    ) as schedule"),
                    'fingerprint as hash',
                    DB::raw('COUNT(*) as total'),
                    DB::raw("SUM(CASE WHEN {$exitCode} = 0 THEN 1 ELSE 0 END) as processed_count"),
                    DB::raw("SUM(CASE WHEN {$exitCode} != 0 AND {$exitCodeValue} IS NOT NULL THEN 1 ELSE 0 END) as failed_count"),
                    DB::raw("SUM(CASE WHEN {$status} = 'skipped' THEN 1 ELSE 0 END) as skipped_count"),
                    DB::raw("AVG({$duration}) as avg_duration"),
                    DB::raw("MAX({$duration}) as p95_duration"),
                ])
                ->groupBy('command', 'schedule', 'fingerprint')
                ->orderBy('total', 'desc')
                ->paginate(20)
                ->through(function ($task) {
                    try {
                        if ($task->schedule) {
                            $cron = new CronExpression($task->schedule);
                            $task->next_run = $cron->getNextRunDate()->format('Y-m-d H:i:s');
                        } else {
                            $task->next_run = 'N/A';
                        }
                    } catch (\Exception $e) {
                        $task->next_run = 'Invalid Schedule';
                    }

                    return $task;
                }),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'scheduled-task', $period, $from, $to),
            'overview' => [
                'total' => (int) ($overview->total ?? 0),
                'success' => (int) ($overview->success ?? 0),
                'failed' => (int) ($overview->failed ?? 0),
                'avg_duration' => round($overview->avg_duration ?? 0, 2),
            ],
        ];
    }

    /**
     * Query Aggregation
     */
    public function getQueryStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $duration = $this->jsonNumeric('duration');

        $overview = $project->records()
            ->ofType('query')
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("AVG({$duration}) as avg_duration"),
            ])->first();

        return [
            'queries' => $project->records()
                ->ofType('query')
                ->forPeriod($period, $from, $to)
                ->select([
                    'fingerprint as hash',
                    // sql is the fingerprint input (fingerprint = md5(sql)); keep
                    // db_connection in the key since the same SQL on a different
                    // connection is a distinct row, but drop the heavy JSON sql
                    // text from the group key — MIN() is value-identical per hash.
                    DB::raw("MIN({$this->jsonText('sql')}) as sql_query"),
                    DB::raw("COALESCE({$this->jsonText('connection')}, 'mysql') as db_connection"),
                    DB::raw('COUNT(*) as total_calls'),
                    DB::raw("AVG({$duration}) as avg_duration"),
                    DB::raw("MAX({$duration}) as p95_duration"),
                    DB::raw("SUM({$duration}) as total_duration"),
                ])
                ->groupBy('hash', 'db_connection')
                ->orderBy('total_calls', 'desc')
                ->paginate(20)->withQueryString(),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'query', $period, $from, $to),
            'overview' => [
                'total' => (int) ($overview->total ?? 0),
                'avg_duration' => round($overview->avg_duration ?? 0, 2),
            ],
        ];
    }

    /**
     * Outgoing Requests Aggregation
     */
    public function getOutgoingRequestStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $statusCode = $this->jsonNumeric('status_code');
        $status = $this->jsonNumeric('status');
        $resolvedStatus = "COALESCE({$statusCode}, {$status})";
        $duration = $this->jsonNumeric('duration');

        $overview = $project->records()
            ->ofType('outgoing-request')
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("SUM(CASE WHEN {$resolvedStatus} BETWEEN 100 AND 399 THEN 1 ELSE 0 END) as ok"),
                DB::raw("SUM(CASE WHEN {$resolvedStatus} >= 400 THEN 1 ELSE 0 END) as failed"),
                DB::raw("AVG({$duration}) as avg_duration"),
            ])->first();

        return [
            'hosts' => $project->records()
                ->ofType('outgoing-request')
                ->forPeriod($period, $from, $to)
                ->select([
                    DB::raw("{$this->jsonText('host')} as host"),
                    'fingerprint as hash',
                    DB::raw('COUNT(*) as total'),
                    DB::raw("SUM(CASE WHEN {$resolvedStatus} BETWEEN 100 AND 399 THEN 1 ELSE 0 END) as ok_count"),
                    DB::raw("SUM(CASE WHEN {$resolvedStatus} BETWEEN 400 AND 499 THEN 1 ELSE 0 END) as client_error_count"),
                    DB::raw("SUM(CASE WHEN {$resolvedStatus} >= 500 THEN 1 ELSE 0 END) as server_error_count"),
                    DB::raw("AVG({$duration}) as avg_duration"),
                    DB::raw("MAX({$duration}) as p95_duration"),
                ])
                ->groupBy('host', 'fingerprint')
                ->orderBy('total', 'desc')
                ->paginate(20)->withQueryString(),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'outgoing-request', $period, $from, $to),
            'overview' => [
                'total' => (int) ($overview->total ?? 0),
                'ok' => (int) ($overview->ok ?? 0),
                'failed' => (int) ($overview->failed ?? 0),
                'avg_duration' => round($overview->avg_duration ?? 0, 2),
            ],
        ];
    }

    /**
     * Cache Aggregation
     */
    public function getCacheStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $cacheType = $this->jsonText('type');

        $overview = $project->records()
            ->ofType('cache-event')
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("SUM(CASE WHEN {$cacheType} = 'hit' THEN 1 ELSE 0 END) as hits"),
                DB::raw("SUM(CASE WHEN {$cacheType} = 'miss' THEN 1 ELSE 0 END) as misses"),
            ])->first();

        return [
            'keys' => $project->records()
                ->ofType('cache-event')
                ->forPeriod($period, $from, $to)
                ->select([
                    DB::raw("{$this->jsonText('key')} as cache_key"),
                    DB::raw('COUNT(*) as total'),
                    DB::raw("SUM(CASE WHEN {$cacheType} = 'hit' THEN 1 ELSE 0 END) as hits"),
                    DB::raw("SUM(CASE WHEN {$cacheType} = 'miss' THEN 1 ELSE 0 END) as misses"),
                    DB::raw("SUM(CASE WHEN {$cacheType} = 'write' THEN 1 ELSE 0 END) as writes"),
                    DB::raw("SUM(CASE WHEN {$cacheType} = 'delete' THEN 1 ELSE 0 END) as deletes"),
                    DB::raw("(SUM(CASE WHEN {$cacheType} = 'hit' THEN 1 ELSE 0 END) * 100 / NULLIF(COUNT(*), 0)) as hit_rate"),
                ])
                ->groupBy('cache_key')
                ->orderBy('total', 'desc')
                ->paginate(20)->withQueryString(),
            'timeSeries' => $this->getDetailedTimeSeries($project, 'cache-event', $period, $from, $to),
            'overview' => [
                'total' => (int) ($overview->total ?? 0),
                'hits' => (int) ($overview->hits ?? 0),
                'misses' => (int) ($overview->misses ?? 0),
                'hit_rate' => $overview->total > 0 ? round(($overview->hits / $overview->total) * 100, 2) : 0,
            ],
        ];
    }

    /**
     * Notification Aggregation
     */
    public function getNotificationStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $channel = $this->jsonDistinct('channel');
        $status = $this->jsonText('status');

        $overview = $project->records()
            ->ofType('notification')
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw("COUNT(DISTINCT {$channel}) as channels_count"),
            ])->first();

        return [
            'notifications' => $project->records()
                ->ofType('notification')
                ->forPeriod($period, $from, $to)
                ->select([
                    'fingerprint as hash',
                    DB::raw("{$this->jsonText('class')} as notification_class"),
                    DB::raw("{$this->jsonText('channel')} as channel"),
                    DB::raw('COUNT(*) as total'),
                    DB::raw("SUM(CASE WHEN {$status} != 'failed' THEN 1 ELSE 0 END) as sent_count"),
                    DB::raw("SUM(CASE WHEN {$status} = 'failed' THEN 1 ELSE 0 END) as failed_count"),
                ])
                ->groupBy('hash', 'notification_class', 'channel')
                ->orderBy('total', 'desc')
                ->paginate(20)->withQueryString(),
            'overview' => [
                'total' => (int) ($overview->total ?? 0),
                'channels' => (int) ($overview->channels_count ?? 0),
            ],
        ];
    }

    /**
     * Mail Aggregation
     */
    public function getMailStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $mailer = $this->jsonText('mailer');

        $overview = $project->records()
            ->ofType('mail')
            ->forPeriod($period, $from, $to)
            ->select([
                DB::raw('COUNT(*) as total'),
                DB::raw('COUNT(DISTINCT fingerprint) as unique_mailables'),
            ])->first();

        return [
            'mailables' => $project->records()
                ->ofType('mail')
                ->forPeriod($period, $from, $to)
                ->select([
                    'fingerprint as hash',
                    DB::raw("{$this->jsonText('class')} as mailable_class"),
                    DB::raw('COUNT(*) as total'),
                    DB::raw("SUM(CASE WHEN {$mailer} = 'log' THEN 0 ELSE 1 END) as queued_count"),
                ])
                ->groupBy('hash', 'mailable_class')
                ->orderBy('total', 'desc')
                ->paginate(20)->withQueryString(),
            'overview' => [
                'total' => (int) ($overview->total ?? 0),
                'unique' => (int) ($overview->unique_mailables ?? 0),
            ],
        ];
    }

    /**
     * Unified History Retriever via Fingerprint
     */
    public function getHistoryByHash(Project $project, string $hash, ?string $period = null, ?string $from = null, ?string $to = null): LengthAwarePaginator
    {
        return $project->records()
            ->where('fingerprint', $hash)
            ->forPeriod($period, $from, $to)
            ->latest()
            ->paginate(50)
            ->through(function ($record) {
                if (isset($record->payload['payload']) && is_array($record->payload['payload'])) {
                    $record->payload = array_merge($record->payload, $record->payload['payload']);
                }

                return $record;
            })
            ->withQueryString();
    }

    /**
     * Get specific user history with additional stats
     */
    public function getUserHistory(Project $project, string $hash, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $userHash = "MD5(COALESCE({$this->jsonText('user')}, 'Anonymous'))";

        $records = $project->records()
            ->whereRaw("{$userHash} = ?", [$hash])
            ->forPeriod($period, $from, $to)
            ->latest()
            ->paginate(50)
            ->withQueryString();

        $first = $records->first();
        $user_name = 'Anonymous';
        $user_email = '';
        $user_id = 'Anonymous';

        if ($first) {
            $p = $first->payload;
            $user_name = $p['user']['name'] ?? $p['user_name'] ?? $p['user'] ?? 'Anonymous';
            $user_email = $p['user']['email'] ?? $p['user_email'] ?? '';
            $user_id = $p['user']['id'] ?? $p['user'] ?? 'Anonymous';
        }

        $details = $this->userDetailsByIds($project, [$user_id]);

        if (isset($details[(string) $user_id])) {
            $user_name = $details[(string) $user_id]['name'] ?: $user_name;
            $user_email = $details[(string) $user_id]['email'] ?: $user_email;
        }

        return [
            'user_name' => $user_name,
            'user_email' => $user_email,
            'user_id' => $user_id,
            'user_identifier' => $user_name, // legacy support
            'records' => $records,
            'stats' => $project->records()->forPeriod($period, $from, $to)
                ->whereRaw("{$userHash} = ?", [$hash])
                ->select([
                    DB::raw('COUNT(*) as total'),
                    DB::raw('MIN(created_at) as first_seen'),
                    DB::raw('MAX(created_at) as last_seen'),
                ])->first(),
        ];
    }

    /**
     * Get general stats methods for other types (Mails, Notifications, etc.)
     */
    public function getMonitoringStats(Project $project, string $type, array $fields, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $select = ['fingerprint as hash', DB::raw('COUNT(*) as total')];
        $groupBy = ['fingerprint'];

        foreach ($fields as $alias => $path) {
            $select[] = DB::raw("{$this->jsonText($path)} as {$alias}");
            $groupBy[] = $alias;
        }

        $key = Str::plural(str_replace('-', '_', $type));

        return [
            $key => $project->records()
                ->ofType($type)
                ->forPeriod($period, $from, $to)
                ->select($select)
                ->groupBy($groupBy)
                ->paginate(20)->withQueryString(),
        ];
    }

    /**
     * Get paginated logs with flattened payload if needed.
     */
    public function getLogRecords(Project $project, ?string $search = null, ?string $period = null, ?string $from = null, ?string $to = null): LengthAwarePaginator
    {
        return $project->records()
            ->ofType('log')
            ->forPeriod($period, $from, $to)
            ->when($search, fn ($q) => $q->where('payload', 'like', '%'.$search.'%'))
            ->latest()
            ->paginate(50)
            ->through(function ($record) {
                if (isset($record->payload['payload']) && is_array($record->payload['payload'])) {
                    $record->payload = array_merge($record->payload, $record->payload['payload']);
                }

                return $record;
            })
            ->withQueryString();
    }

    /**
     * Common method to paginate records for a specific type.
     */
    public function getPaginatedRecords(Project $project, string $type, ?string $search = null, ?string $period = null, ?string $from = null, ?string $to = null): LengthAwarePaginator
    {
        $typeMap = [
            'job' => 'job-attempt',
            'cache' => 'cache-event',
        ];

        $actualType = $typeMap[$type] ?? $type;

        return $project->records()
            ->ofType($actualType)
            ->forPeriod($period, $from, $to)
            ->when($search, fn ($q) => $q->where('payload', 'like', '%'.$search.'%'))
            ->latest()
            ->paginate(50)
            ->withQueryString();
    }

    /**
     * Security Threats Aggregation
     */
    public function getSecurityStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $records = $project->records()->ofType('request')->forPeriod($period, $from, $to);
        $ip = $this->jsonDistinct('ip');
        $status = $this->jsonText('status');

        $overview = (clone $records)->select([
            DB::raw("COUNT(DISTINCT {$ip}) as unique_ips"),
            DB::raw('COUNT(*) as total_requests'),
        ])->first();

        // Failed logins (last 24h or selected period)
        $failedLogins = $project->records()
            ->ofType('auth-event')
            ->forPeriod($period, $from, $to)
            ->whereRaw("{$status} = 'failed'")
            ->count();

        // Recent suspicious auth events
        $recentAuthEvents = $project->records()
            ->ofType('auth-event')
            ->forPeriod($period, $from, $to)
            ->whereRaw("{$status} = 'failed'")
            ->latest()
            ->limit(5)
            ->get()
            ->map(fn ($r) => [
                'user' => $r->payload['user'] ?? $r->payload['email'] ?? 'Anonymous',
                'ip' => $r->payload['ip'] ?? 'Unknown',
                'type' => $r->payload['event_type'] ?? 'Login Failure',
                'location' => $r->payload['location'] ?? 'Unknown',
                'time' => $r->created_at->diffForHumans(),
            ]);

        return [
            'threats' => $project->issues()
                ->where('type', 'security')
                ->where('project_id', $project->id)
                ->select([
                    'id',
                    'hash',
                    'title',
                    'message',
                    'occurrences_count',
                    'last_seen_at',
                ])
                ->orderBy('last_seen_at', 'desc')
                ->paginate(20)->withQueryString(),
            'overview' => [
                'unique_ips' => (int) ($overview->unique_ips ?? 0),
                'total_scanned' => (int) ($overview->total_requests ?? 0),
                'failed_logins' => $failedLogins,
                'recent_auth_events' => $recentAuthEvents,
            ],
        ];
    }

    /**
     * Time series aggregation for dashboards
     */
    protected function getDetailedTimeSeries(Project $project, string $type, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $period = $period ?: '1h';
        $query = $project->records()
            ->ofType($type)
            ->forPeriod($period, $from, $to);

        $timeBucket = $this->timeBucketSql($period);
        $statusCode = $this->jsonNumeric('status_code');
        $status = $this->jsonText('status');
        $exitCode = $this->jsonNumeric('exit_code');
        $exitCodeValue = $this->jsonValue('exit_code');
        $cacheType = $this->jsonText('type');
        $duration = $this->jsonNumeric('duration');
        $user = $this->jsonDistinct('user');

        $results = $query->select([
            DB::raw("{$timeBucket} as minute"),
            DB::raw('COUNT(*) as total'),
            DB::raw("SUM(CASE
                WHEN {$statusCode} BETWEEN 100 AND 399 THEN 1
                WHEN {$status} = 'processed' THEN 1
                WHEN {$exitCode} = 0 THEN 1
                WHEN {$cacheType} = 'hit' THEN 1
                ELSE 0
            END) as ok"),
            DB::raw("SUM(CASE
                WHEN {$statusCode} BETWEEN 400 AND 499 THEN 1
                ELSE 0
            END) as client_error"),
            DB::raw("SUM(CASE
                WHEN {$statusCode} >= 500 THEN 1
                WHEN {$status} = 'failed' THEN 1
                WHEN type = 'exception' THEN 1
                WHEN {$exitCode} != 0 AND {$exitCodeValue} IS NOT NULL THEN 1
                WHEN {$cacheType} = 'miss' THEN 1
                ELSE 0
            END) as server_error"),
            DB::raw("AVG({$duration}) as avg_duration"),
            DB::raw("SUM(CASE WHEN {$cacheType} = 'hit' THEN 1 ELSE 0 END) as hits"),
            DB::raw("SUM(CASE WHEN {$cacheType} = 'miss' THEN 1 ELSE 0 END) as misses"),
            DB::raw("SUM(CASE WHEN {$cacheType} = 'write' THEN 1 ELSE 0 END) as writes"),
            DB::raw("COUNT(DISTINCT {$user}) as active_users"),
            DB::raw('COUNT(*) as total_requests'),
        ])
            ->groupBy('minute')
            ->get()
            ->keyBy('minute');

        return $this->fillTimeSeriesGaps($results, $period, $from, $to);
    }

    /**
     * Fill missing time slots with zeroed data.
     */
    protected function fillTimeSeriesGaps($results, string $period, ?string $from = null, ?string $to = null): array
    {
        $data = [];
        $now = now();

        $iterations = match ($period) {
            '1h' => 60,
            '24h' => 1440,
            '7d' => 7,
            '14d' => 14,
            '30d' => 30,
            default => 60,
        };

        $unit = match ($period) {
            '7d', '14d', '30d' => 'day',
            default => 'minute',
        };

        $dateFormat = match ($period) {
            '7d', '14d', '30d' => 'm-d',
            '24h' => 'H:i',
            default => 'H:i',
        };

        for ($i = $iterations - 1; $i >= 0; $i--) {
            $time = (clone $now)->sub($unit, $i);
            $key = $time->format($dateFormat);

            if ($results->has($key)) {
                $data[] = $results->get($key);
            } else {
                $data[] = [
                    'minute' => $key,
                    'total' => 0,
                    'ok' => 0,
                    'client_error' => 0,
                    'server_error' => 0,
                    'avg_duration' => 0,
                    'hits' => 0,
                    'misses' => 0,
                    'writes' => 0,
                    'active_users' => 0,
                    'total_requests' => 0,
                ];
            }
        }

        return $data;
    }

    private function enrichUserPaginator(Project $project, LengthAwarePaginator $paginator): LengthAwarePaginator
    {
        $this->enrichUserRows($project, $paginator->getCollection());

        return $paginator;
    }

    private function enrichUserRows(Project $project, iterable $rows): void
    {
        $ids = collect($rows)
            ->map(fn ($row) => (string) ($row->user_id ?? $row->user_identifier ?? $row->user_name ?? ''))
            ->filter(fn (string $id) => $id !== '' && $id !== 'Anonymous')
            ->unique()
            ->values();

        if ($ids->isEmpty()) {
            return;
        }

        $details = $this->userDetailsByIds($project, $ids->all());

        foreach ($rows as $row) {
            $id = (string) ($row->user_id ?? $row->user_identifier ?? $row->user_name ?? '');
            $detail = $details[$id] ?? null;

            if (! $detail) {
                continue;
            }

            if (($row->user_name ?? $row->user_identifier ?? '') === $id && $detail['name'] !== '') {
                $row->user_name = $detail['name'];
                $row->user_identifier = $detail['name'];
            }

            if (($row->user_email ?? '') === '' && $detail['email'] !== '') {
                $row->user_email = $detail['email'];
            }
        }
    }

    /**
     * @param  array<int, int|string>  $ids
     * @return array<string, array{name: string, email: string}>
     */
    private function userDetailsByIds(Project $project, array $ids): array
    {
        $ids = collect($ids)
            ->map(fn (int|string $id): string => (string) $id)
            ->filter(fn (string $id): bool => $id !== '' && $id !== 'Anonymous')
            ->unique()
            ->values();

        if ($ids->isEmpty()) {
            return [];
        }

        $details = [];

        $project->records()
            ->ofType('user')
            ->whereIn(DB::raw($this->jsonText('id')), $ids->all())
            ->latest()
            ->get(['payload'])
            ->each(function ($record) use (&$details): void {
                $payload = $record->payload;
                $id = (string) ($payload['id'] ?? '');

                if ($id === '' || isset($details[$id])) {
                    return;
                }

                $username = (string) ($payload['username'] ?? '');

                $details[$id] = [
                    'name' => (string) ($payload['name'] ?? ''),
                    'email' => filter_var($payload['email'] ?? $username, FILTER_VALIDATE_EMAIL) ? (string) ($payload['email'] ?? $username) : '',
                ];
            });

        return $details;
    }

    public function getUptimeStats(Project $project, ?string $period = null, ?string $from = null, ?string $to = null): array
    {
        $query = $project->uptimeChecks()
            ->orderBy('checked_at', 'desc');

        if ($period && $period !== 'all') {
            $minutes = match ($period) {
                '1h' => 60,
                '24h' => 1440,
                '7d' => 10080,
                '30d' => 43200,
                default => 1440
            };
            $query->where('checked_at', '>=', now()->subMinutes($minutes));
        }

        $checks = $query->paginate(50)->withQueryString();

        $totalChecks = $project->uptimeChecks()->count();
        $upChecks = $project->uptimeChecks()->where('status', 'up')->count();

        $stats = [
            'uptime_percentage' => $totalChecks > 0 ? round(($upChecks / $totalChecks) * 100, 2) : 100,
            'avg_response_time' => round($project->uptimeChecks()->avg('response_time') ?? 0, 2),
            'last_check' => $project->uptimeChecks()->latest('checked_at')->first(),
            'total_checks' => $totalChecks,
        ];

        return [
            'checks' => $checks,
            'uptime_stats' => $stats,
        ];
    }

    public function getSecurityHistoryByHash(Project $project, string $hash, ?string $period = '24h', ?string $from = null, ?string $to = null): array
    {
        $issue = $project->issues()
            ->where('hash', $hash)
            ->firstOrFail();

        $records = $project->records()
            ->where(function ($q) use ($hash, $issue) {
                $q->where('issue_id', $issue->id)
                    ->orWhere(function ($sq) use ($hash) {
                        $sq->where('type', 'request')
                            ->where(function ($ssq) use ($hash) {
                                $ssq->whereJsonContains('payload->_security_threats', [['hash' => $hash]])
                                    ->orWhereJsonContains('payload->_security_changes', [['hash' => $hash]]);
                            });
                    });
            })
            ->forPeriod($period, $from, $to)
            ->orderBy('created_at', 'desc')
            ->paginate(50)
            ->withQueryString();

        return [
            'hash' => $hash,
            'meta' => [
                'title' => $issue->title,
                'message' => $issue->message,
                'occurrences' => $issue->occurrences_count,
                'last_seen_at' => $issue->last_seen_at,
            ],
            'records' => $records,
            'period' => $period,
        ];
    }

    private function isPgsql(): bool
    {
        return DB::connection()->getDriverName() === 'pgsql';
    }

    private function jsonPathSegments(string $path): array
    {
        return explode('.', $path);
    }

    private function quoteLiteral(string $value): string
    {
        return "'".str_replace("'", "''", $value)."'";
    }

    private function jsonValue(string $path): string
    {
        if ($this->isPgsql()) {
            $segments = array_map([$this, 'quoteLiteral'], $this->jsonPathSegments($path));

            return 'payload #> ARRAY['.implode(', ', $segments).']';
        }

        return "JSON_EXTRACT(payload, '$.".$path."')";
    }

    private function jsonText(string $path): string
    {
        if ($this->isPgsql()) {
            $segments = array_map([$this, 'quoteLiteral'], $this->jsonPathSegments($path));

            return 'payload #>> ARRAY['.implode(', ', $segments).']';
        }

        return "JSON_UNQUOTE(JSON_EXTRACT(payload, '$.".$path."'))";
    }

    private function jsonNumeric(string $path): string
    {
        $text = $this->jsonText($path);

        if ($this->isPgsql()) {
            $trimmed = "NULLIF(BTRIM({$text}), '')";

            return "CASE WHEN {$trimmed} ~ '^[+-]?([0-9]+([.][0-9]+)?|[.][0-9]+)$' THEN ({$trimmed})::numeric ELSE NULL END";
        }

        return "CAST(NULLIF({$text}, '') AS DECIMAL(20,6))";
    }

    private function jsonDistinct(string $path): string
    {
        if ($this->isPgsql()) {
            return '('.$this->jsonValue($path).')::text';
        }

        return 'CAST('.$this->jsonValue($path).' AS CHAR)';
    }

    private function timeBucketSql(string $period): string
    {
        if ($this->isPgsql()) {
            return match ($period) {
                '7d', '14d', '30d' => "to_char(created_at, 'MM-DD')",
                'custom' => "to_char(date_trunc('hour', created_at), 'YYYY-MM-DD HH24:00')",
                default => "to_char(created_at, 'HH24:MI')",
            };
        }

        return match ($period) {
            '7d', '14d', '30d' => "DATE_FORMAT(created_at, '%m-%d')",
            'custom' => "DATE_FORMAT(created_at, '%Y-%m-%d %H:00')",
            default => "DATE_FORMAT(created_at, '%H:%i')",
        };
    }
}
