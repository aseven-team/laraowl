<?php

use App\Models\Project;
use App\Models\Record;
use App\Services\RecordService;

it('handles non numeric outgoing request status values without SQL errors', function () {
    $project = Project::factory()->create();

    Record::create([
        'project_id' => $project->id,
        'type' => 'outgoing-request',
        'fingerprint' => 'failed-status',
        'payload' => [
            'host' => 'api.example.com',
            'status' => 'failed',
            'duration' => 125,
        ],
        'created_at' => now(),
    ]);

    Record::create([
        'project_id' => $project->id,
        'type' => 'outgoing-request',
        'fingerprint' => 'ok-status',
        'payload' => [
            'host' => 'api.example.com',
            'status_code' => 200,
            'duration' => 75,
        ],
        'created_at' => now(),
    ]);

    $stats = app(RecordService::class)->getOutgoingRequestStats($project, '24h');

    expect($stats['overview'])
        ->toMatchArray([
            'total' => 2,
            'ok' => 1,
            'failed' => 0,
        ]);

    expect($stats['hosts']->total())->toBe(2);
});

it('aggregates request stats by fingerprint, merging rows with the same signature', function () {
    $project = Project::factory()->create();

    // Two hits on the same route+method (same fingerprint) plus one different route.
    foreach ([200, 500] as $status) {
        Record::create([
            'project_id' => $project->id,
            'type' => 'request',
            'fingerprint' => md5('GET/users'),
            'payload' => ['method' => 'GET', 'route_path' => '/users', 'status_code' => $status, 'duration' => 100],
            'created_at' => now(),
        ]);
    }

    Record::create([
        'project_id' => $project->id,
        'type' => 'request',
        'fingerprint' => md5('POST/orders'),
        'payload' => ['method' => 'POST', 'route_path' => '/orders', 'status_code' => 201, 'duration' => 200],
        'created_at' => now(),
    ]);

    $stats = app(RecordService::class)->getRequestStats($project, '24h');

    expect($stats['requests']->total())->toBe(2);

    $byHash = $stats['requests']->getCollection()->keyBy('hash');

    expect((int) $byHash[md5('GET/users')]->total)->toBe(2)
        ->and($byHash[md5('GET/users')]->method)->toBe('GET')
        ->and($byHash[md5('GET/users')]->path)->toBe('/users')
        ->and((int) $byHash[md5('GET/users')]->ok_count)->toBe(1)
        ->and((int) $byHash[md5('GET/users')]->server_error_count)->toBe(1);
});

it('aggregates exception stats by fingerprint', function () {
    $project = Project::factory()->create();

    foreach (range(1, 3) as $i) {
        Record::create([
            'project_id' => $project->id,
            'type' => 'exception',
            'fingerprint' => md5('RuntimeExceptionboom'),
            'payload' => ['class' => 'RuntimeException', 'message' => 'boom'],
            'created_at' => now(),
        ]);
    }

    $stats = app(RecordService::class)->getExceptionStats($project, '24h');

    expect($stats['exceptions']->total())->toBe(1);

    $row = $stats['exceptions']->getCollection()->first();
    expect((int) $row->total_count)->toBe(3)
        ->and($row->class)->toBe('RuntimeException')
        ->and($row->message)->toBe('boom');
});

it('aggregates job stats by fingerprint', function () {
    $project = Project::factory()->create();

    foreach (['processed', 'failed'] as $status) {
        Record::create([
            'project_id' => $project->id,
            'type' => 'job-attempt',
            'fingerprint' => md5('App\\Jobs\\SendMail'),
            'payload' => ['job' => 'App\\Jobs\\SendMail', 'status' => $status, 'duration' => 50],
            'created_at' => now(),
        ]);
    }

    $stats = app(RecordService::class)->getJobStats($project, '24h');

    expect($stats['jobs']->total())->toBe(1);

    $row = $stats['jobs']->getCollection()->first();
    expect((int) $row->total)->toBe(2)
        ->and($row->job_class)->toBe('App\\Jobs\\SendMail')
        ->and((int) $row->processed_count)->toBe(1)
        ->and((int) $row->failed_count)->toBe(1);
});

it('keeps queries with the same sql but different connections separate', function () {
    $project = Project::factory()->create();

    foreach (['mysql', 'pgsql'] as $connection) {
        Record::create([
            'project_id' => $project->id,
            'type' => 'query',
            'fingerprint' => md5('select * from users'),
            'payload' => ['sql' => 'select * from users', 'connection' => $connection, 'duration' => 10],
            'created_at' => now(),
        ]);
    }

    $stats = app(RecordService::class)->getQueryStats($project, '24h');

    // Same fingerprint, two connections -> must stay two rows.
    expect($stats['queries']->total())->toBe(2);

    $byConnection = $stats['queries']->getCollection()->keyBy('db_connection');
    expect($byConnection['mysql']->sql_query)->toBe('select * from users')
        ->and($byConnection['pgsql']->sql_query)->toBe('select * from users');
});
