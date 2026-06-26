<?php

namespace App\Jobs;

use App\Models\Project;
use App\Models\Record;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

/**
 * Confirms directory listing by probing the project's app URL from outside — the
 * only reliable method (the client heuristic can't see Nginx autoindex). Requires
 * a 200 AND a known listing signature in the body; status alone is a false positive.
 */
class ProbeDirectoryListing implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public $tries = 2;

    /** Listing markers across Apache, IIS, Nginx autoindex, Python http.server. */
    private const SIGNATURES = ['index of /', 'parent directory', 'directory listing for', '<title>index of'];

    /** Index-less dirs that commonly exist in a Laravel public root. */
    private const CANDIDATES = ['storage', 'build', 'css', 'js'];

    public function __construct(
        public Project $project,
        public Record $record,
        public string $appUrl,
    ) {}

    public function handle(): void
    {
        if (! $this->isProbeable($this->appUrl)) {
            return; // SSRF guard
        }

        foreach (self::CANDIDATES as $dir) {
            $url = rtrim($this->appUrl, '/')."/{$dir}/";

            $res = rescue(fn () => Http::timeout(5)->connectTimeout(3)
                ->withoutRedirecting()->get($url), null, false);

            if (! $res || ! $res->ok()) {
                continue;
            }

            $body = strtolower($res->body());
            foreach (self::SIGNATURES as $sig) {
                if (str_contains($body, $sig)) {
                    $this->report($url);

                    return;
                }
            }
        }
    }

    /**
     * SSRF guard: only http(s) hosts resolving to a public IP. IPv4-only and
     * doesn't pin the connection IP, so it won't stop DNS rebinding.
     */
    private function isProbeable(string $url): bool
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $host = parse_url($url, PHP_URL_HOST);

        if (! $host || ! in_array($scheme, ['http', 'https'], true)) {
            return false;
        }

        $ip = gethostbyname($host); // returns $host unchanged on failure
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    private function report(string $evidence): void
    {
        $hash = md5("security_dirlist_{$this->project->id}");

        $issue = $this->project->issues()->firstOrCreate(
            ['hash' => $hash],
            [
                'type' => 'security',
                'title' => 'Security Audit: Directory listing enabled',
                'message' => Str::limit("Directory listing is enabled and externally confirmed at {$evidence}", 500),
                'status' => 'open',
                'priority' => 'medium',
                'first_seen_at' => now(),
                'last_seen_at' => now(),
            ]
        );

        $issue->increment('occurrences_count');
        $issue->update([
            'last_seen_at' => now(),
            'status' => 'open',
            'message' => Str::limit("Directory listing is enabled and externally confirmed at {$evidence}", 500),
        ]);

        $this->record->update(['issue_id' => $issue->id]);
    }
}
