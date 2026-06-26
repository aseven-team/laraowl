<?php

namespace Tests\Feature;

use App\Jobs\ProbeDirectoryListing;
use App\Models\Project;
use App\Models\Record;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class ProbeDirectoryListingTest extends TestCase
{
    use RefreshDatabase;

    public function test_it_reports_an_issue_when_listing_is_externally_confirmed()
    {
        $project = Project::factory()->create();
        $record = Record::factory()->create(['project_id' => $project->id, 'type' => 'security-audit']);

        // 200 + a listing signature in the body = confirmed.
        Http::fake(['*' => Http::response('<html><head><title>Index of /storage</title></head><body>Parent Directory</body></html>', 200)]);

        (new ProbeDirectoryListing($project, $record, 'https://example.com'))->handle();

        $issue = $project->issues()->where('hash', md5("security_dirlist_{$project->id}"))->first();
        $this->assertNotNull($issue);
        $this->assertSame('Security Audit: Directory listing enabled', $issue->title);
        $this->assertSame($issue->id, $record->fresh()->issue_id);
    }

    public function test_it_does_not_report_when_server_blocks_listing()
    {
        $project = Project::factory()->create();
        $record = Record::factory()->create(['project_id' => $project->id, 'type' => 'security-audit']);

        // 403/404 with no listing signature = nothing to report (the 200-only false positive trap).
        Http::fake(['*' => Http::response('Forbidden', 403)]);

        (new ProbeDirectoryListing($project, $record, 'https://example.com'))->handle();

        $this->assertSame(0, $project->issues()->count());
    }

    public function test_it_refuses_to_probe_private_hosts()
    {
        $project = Project::factory()->create();
        $record = Record::factory()->create(['project_id' => $project->id, 'type' => 'security-audit']);

        Http::fake(); // any outbound call would be a fail

        (new ProbeDirectoryListing($project, $record, 'http://127.0.0.1'))->handle();

        Http::assertNothingSent();
        $this->assertSame(0, $project->issues()->count());
    }
}
