<?php

namespace App\Services;

use App\Jobs\ProbeDirectoryListing;
use App\Models\Project;
use App\Models\Record;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

class SecurityService
{
    const SCORE_THRESHOLD_MEDIUM = 30;

    const SCORE_THRESHOLD_HIGH = 70;

    const SCORE_THRESHOLD_CRITICAL = 100;

    /**
     * Advanced threat patterns with assigned risk scores.
     */
    protected array $threatPatterns = [
        'sqli' => [
            'patterns' => [
                "/'\s*OR\s*['\"]?1['\"]?\s*=\s*['\"]?1/",
                "/UNION\s+SELECT/i",
                "/DROP\s+TABLE/i",
                "/SLEEP\s*\(/i",
                '/INFORMATION_SCHEMA/i',
                "/GROUP\s+BY\s+\d+/i",
                "/ORDER\s+BY\s+\d+/i",
            ],
            'score' => 40,
        ],
        'xss' => [
            'patterns' => [
                '/<script/i',
                '/javascript:/i',
                "/onerror\s*=/i",
                "/onload\s*=/i",
                '/<iframe/i',
                "/document\.cookie/i",
                "/alert\s*\(/i",
                "/prompt\s*\(/i",
                "/string\.fromcharcode/i",
            ],
            'score' => 30,
        ],
        'path_traversal' => [
            'patterns' => [
                "/\.\.\//",
                "/\/etc\/passwd/",
                "/\.env/",
                "/config\/database\.php/",
                "/\.git\//",
                "/\.htaccess/",
                "/proc\/self/i",
            ],
            'score' => 50,
        ],
        'command_injection' => [
            'patterns' => [
                "/;\s*cat\s+/i",
                "/\|\s*grep\s+/i",
                "/&&\s*ls/i",
                "/system\s*\(/i",
                "/exec\s*\(/i",
                "/passthru\s*\(/i",
                "/shell_exec\s*\(/i",
                "/curl\s+.*\|\s*sh/i",
            ],
            'score' => 60,
        ],
        'lfi_rfi' => [
            'patterns' => [
                "/php:\/\/filter/i",
                "/https?:\/\/.*\.(txt|php|exe)/i",
                "/expect:\/\//i",
            ],
            'score' => 50,
        ],
    ];

    /**
     * Analyze a record for potential security threats.
     */
    public function analyze(Project $project, Record $record): void
    {
        if ($record->type !== 'request') {
            return;
        }

        $payload = $record->payload;
        $ip = $payload['ip'] ?? 'unknown';
        $detectedThreats = [];
        $totalScore = 0;

        // 1. De-obfuscate and Prepare Inputs
        $rawInputs = [
            'url' => $payload['url'] ?? '',
            'query' => json_encode($payload['query'] ?? []),
            'body' => is_array($payload['payload'] ?? null) ? json_encode($payload['payload']) : ($payload['payload'] ?? ''),
            'headers' => is_array($payload['headers'] ?? null) ? json_encode($payload['headers']) : ($payload['headers'] ?? ''),
        ];

        $preparedInputs = [];
        foreach ($rawInputs as $key => $val) {
            $decoded = urldecode($val);
            $preparedInputs[$key] = $decoded;

            // Check for potential Base64/Hex obfuscation
            if ($this->isObfuscated($decoded)) {
                $preparedInputs[$key.'_decoded'] = $this->deobfuscate($decoded);
                $totalScore += 10; // Penalty for obfuscated payload
            }
        }

        // 2. Pattern Matching
        foreach ($preparedInputs as $source => $value) {
            foreach ($this->threatPatterns as $type => $config) {
                foreach ($config['patterns'] as $pattern) {
                    if (preg_match($pattern, $value)) {
                        $detectedThreats[] = [
                            'type' => $type,
                            'source' => $source,
                            'pattern' => $pattern,
                        ];
                        $totalScore += $config['score'];
                    }
                }
            }
        }

        // 3. Anomaly Detection (Scanner, UA, Status Codes)
        $anomalies = $this->detectAnomalies($project, $ip, $payload);
        if (! empty($anomalies)) {
            foreach ($anomalies as $anomaly) {
                $detectedThreats[] = $anomaly;
                $totalScore += $anomaly['score'];
            }
        }

        if (! empty($detectedThreats)) {
            $this->processThreats($project, $record, $detectedThreats, $totalScore);
        }
    }

    /**
     * Detect anomalies like rapid 404s (Scanning) or suspicious Headers.
     */
    protected function detectAnomalies(Project $project, string $ip, array $payload): array
    {
        $anomalies = [];
        $cachePrefix = "sec_anom_{$project->id}_{$ip}_";

        // A. Scanner Detection (Too many 404s)
        if (($payload['status_code'] ?? 200) === 404) {
            $key = $cachePrefix.'404_count';
            $count = Cache::increment($key);
            Cache::put($key, $count, 60); // Reset every minute

            if ($count > 10) {
                $anomalies[] = [
                    'type' => 'anomaly',
                    'detail' => 'Directory Scanning Detected (Rapid 404s)',
                    'score' => 20,
                ];
            }
        }

        // B. User-Agent Anomaly
        $ua = $payload['headers']['user-agent'] ?? '';
        $suspiciousBots = ['sqlmap', 'nmap', 'nikto', 'dirbuster', 'gobuster', 'python-requests'];
        foreach ($suspiciousBots as $bot) {
            if (Str::contains(strtolower($ua), $bot)) {
                $anomalies[] = [
                    'type' => 'anomaly',
                    'detail' => "Suspicious Security Tool Detected: $bot",
                    'score' => 40,
                ];
            }
        }

        return $anomalies;
    }

    /**
     * Check if a string looks like it contains Base64 or Hex.
     */
    protected function isObfuscated(string $value): bool
    {
        // Check for long Base64-like strings or hex sequences
        return preg_match('/[a-zA-Z0-9+\/]{20,}={0,2}/', $value) ||
               preg_match('/(?:[0-9a-fA-F]{2}\s*){8,}/', $value);
    }

    /**
     * Attempt to de-obfuscate a string.
     */
    protected function deobfuscate(string $value): string
    {
        // Try Base64
        $decoded = base64_decode($value, true);
        if ($decoded !== false && ctype_print($decoded)) {
            return 'BASE64_DECODED: '.$decoded;
        }

        // Try Hex
        $hex = preg_replace('/\s+/', '', $value);
        if (ctype_xdigit($hex) && strlen($hex) > 10) {
            $bin = @hex2bin($hex);
            if ($bin !== false && ctype_print($bin)) {
                return 'HEX_DECODED: '.$bin;
            }
        }

        return $value;
    }

    /**
     * Process threats and update IP reputation.
     */
    protected function processThreats(Project $project, Record $record, array $threats, int $roundScore): void
    {
        $ip = $record->payload['ip'] ?? 'unknown';
        $repKey = "sec_rep_{$project->id}_{$ip}";

        // Cumulative Score
        $cumulativeScore = Cache::get($repKey, 0) + $roundScore;
        Cache::put($repKey, $cumulativeScore, 3600 * 24); // Store for 24h

        $riskLevel = $this->getRiskLevel($cumulativeScore);

        // Report
        $hash = md5("security_{$riskLevel}_{$ip}");
        $title = 'Security Issue: '.strtoupper($riskLevel)." Risk from $ip";
        $message = "Cumulative Threat Score: $cumulativeScore. Detected: ".collect($threats)->pluck('type')->unique()->implode(', ');

        $issue = $project->issues()->firstOrCreate(
            ['hash' => $hash],
            [
                'type' => 'security',
                'title' => $title,
                'message' => $message,
                'status' => 'open',
                'priority' => $this->getPriority($riskLevel),
                'first_seen_at' => now(),
                'last_seen_at' => now(),
            ]
        );

        $issue->increment('occurrences_count');
        $issue->update([
            'last_seen_at' => now(),
            'message' => $message,
        ]);

        $record->update(['issue_id' => $issue->id]);

        // Tag the record
        $payload = $record->payload;
        $payload['_security_threats'] = $threats;
        $payload['_security_score'] = $cumulativeScore;
        $payload['_security_risk'] = $riskLevel;
        $record->update(['payload' => $payload]);
    }

    protected function getRiskLevel(int $score): string
    {
        if ($score >= self::SCORE_THRESHOLD_CRITICAL) {
            return 'critical';
        }
        if ($score >= self::SCORE_THRESHOLD_HIGH) {
            return 'high';
        }
        if ($score >= self::SCORE_THRESHOLD_MEDIUM) {
            return 'medium';
        }

        return 'low';
    }

    protected function getPriority(string $risk): string
    {
        return match ($risk) {
            'critical' => 'critical',
            'high' => 'high',
            'medium' => 'medium',
            default => 'low',
        };
    }

    public function audit(Project $project, Record $record): void
    {
        $payload = $record->payload['payload'] ?? [];
        $hashes = $payload['hashes'] ?? [];
        $env = $payload['environment'] ?? [];
        $publicFiles = $payload['public_files'] ?? [];

        $securityIssues = [];

        // 1. File Integrity Check
        $settings = $project->settings ?? [];
        $oldHashes = $settings['security_hashes'] ?? [];
        $hashChanges = $this->compareHashes($oldHashes, $hashes);

        if (! empty($hashChanges)) {
            $securityIssues[] = [
                'type' => 'file_integrity',
                'details' => $hashChanges,
                'priority' => 'critical',
            ];
        }

        // 2. Environment Audit
        if (($env['app_debug'] ?? false) && ($env['app_env'] ?? '') === 'production') {
            $securityIssues[] = [
                'type' => 'environment',
                'details' => 'APP_DEBUG is enabled in production environment',
                'priority' => 'high',
            ];
        }

        if (! ($env['session_secure'] ?? true)) {
            $securityIssues[] = [
                'type' => 'configuration',
                'details' => 'Session cookies are not set to Secure',
                'priority' => 'medium',
            ];
        }

        // 3. Public Folder Audit
        if (! empty($publicFiles['suspicious_files_found'] ?? [])) {
            $securityIssues[] = [
                'type' => 'suspicious_files',
                'details' => 'Suspicious files found in public folder: '.implode(', ', $publicFiles['suspicious_files_found']),
                'priority' => 'high',
            ];
        }

        // The client flag is an unreliable Apache-only heuristic, so verify by
        // external probe unless the client is certain listing is off. afterCommit:
        // audit() runs inside the ingest DB transaction.
        $dirListing = $publicFiles['directory_listing_enabled'] ?? null;
        $appUrl = $env['app_url'] ?? null;
        if ($dirListing !== false && $appUrl) {
            ProbeDirectoryListing::dispatch($project, $record, $appUrl)->afterCommit();
        }

        // 4. Dependency Analysis (Simple version)
        $deps = $payload['dependencies'] ?? [];
        if (($deps['count'] ?? 0) > 200) {
            $securityIssues[] = [
                'type' => 'dependencies',
                'details' => 'Large number of dependencies detected ('.$deps['count'].'). Increase attack surface.',
                'priority' => 'low',
            ];
        }

        // Report Issues
        if (! empty($securityIssues)) {
            $this->reportSecurityAuditIssues($project, $record, $securityIssues);
        }

        // Update the baseline
        $settings['security_hashes'] = $hashes;
        $settings['security_env'] = $env;
        $settings['last_audit_at'] = now()->toDateTimeString();
        $project->update(['settings' => $settings]);
    }

    protected function compareHashes(array $old, array $new): array
    {
        $changes = [];
        foreach ($new as $file => $hash) {
            if (isset($old[$file]) && $old[$file] !== $hash) {
                $changes[] = ['file' => $file, 'type' => 'modified'];
            } elseif (! isset($old[$file])) {
                $changes[] = ['file' => $file, 'type' => 'added'];
            }
        }

        foreach ($old as $file => $hash) {
            if (! isset($new[$file])) {
                $changes[] = ['file' => $file, 'type' => 'deleted'];
            }
        }

        return $changes;
    }

    protected function reportSecurityAuditIssues(Project $project, Record $record, array $issues): void
    {
        $hash = md5("security_audit_{$project->id}");
        $highestPriority = 'low';
        $priorities = ['low', 'medium', 'high', 'critical'];

        foreach ($issues as $issue) {
            if (array_search($issue['priority'], $priorities) > array_search($highestPriority, $priorities)) {
                $highestPriority = $issue['priority'];
            }
        }

        $title = 'Security Audit: '.count($issues).' issues detected';
        $message = collect($issues)->pluck('details')->flatten()->implode('; ');

        $issueModel = $project->issues()->firstOrCreate(
            ['hash' => $hash],
            [
                'type' => 'security',
                'title' => $title,
                'message' => Str::limit($message, 500),
                'status' => 'open',
                'priority' => $highestPriority,
                'first_seen_at' => now(),
                'last_seen_at' => now(),
            ]
        );

        $issueModel->increment('occurrences_count');
        $issueModel->update([
            'last_seen_at' => now(),
            'message' => Str::limit($message, 500),
            'priority' => $highestPriority,
        ]);

        $record->update(['issue_id' => $issueModel->id]);

        // Tag the record
        $payload = $record->payload;
        $payload['_security_audit_issues'] = $issues;
        $record->update(['payload' => $payload]);
    }

    /**
     * Report file integrity issues.
     */
    protected function reportIntegrityIssue(Project $project, Record $record, array $changes): void
    {
        $ip = $record->payload['ip'] ?? 'unknown';
        $hash = md5("security_fim_{$project->id}");

        $title = 'Security: File Integrity Change Detected';
        $message = "Unauthorized file changes detected on server ($ip). ".count($changes).' items affected.';

        $issue = $project->issues()->firstOrCreate(
            ['hash' => $hash],
            [
                'type' => 'security',
                'title' => $title,
                'message' => $message,
                'status' => 'open',
                'priority' => 'critical',
                'first_seen_at' => now(),
                'last_seen_at' => now(),
            ]
        );

        $issue->increment('occurrences_count');
        $issue->update([
            'last_seen_at' => now(),
            'message' => $message,
        ]);

        $record->update(['issue_id' => $issue->id]);

        // Tag the record
        $payload = $record->payload;
        $payload['_security_changes'] = $changes;
        $record->update(['payload' => $payload]);
    }
}
