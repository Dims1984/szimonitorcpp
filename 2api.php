<?php
declare(strict_types=1);

/**
 * szimonitorcpp - Backend Synchronization Endpoint
 * Production-hardened PHP + SQLite3 inventory receiver
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);
    exit;
}

// Enforce strict environment token configuration (no insecure fallback)
$expectedToken = getenv('SZI_API_TOKEN');
if (!is_string($expectedToken) || strlen($expectedToken) < 16) {
    error_log('Critical: SZI_API_TOKEN environment variable is missing or too short.');
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Server Configuration Error']);
    exit;
}

// Timing-attack safe Bearer token verification
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$expectedHeader = 'Bearer ' . $expectedToken;
if (!hash_equals($expectedHeader, $authHeader)) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

// Limit request payload size to 64 KB to prevent DoS
$rawInput = file_get_contents('php://input', false, null, 0, 65536);
if ($rawInput === false || strlen($rawInput) === 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Empty request body']);
    exit;
}

$data = json_decode($rawInput, true, 8);
if (!is_array($data) || empty($data['hostname']) || empty($data['serial_number'])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid JSON payload']);
    exit;
}

$dbPath = __DIR__ . '/inventory.db';

try {
    $pdo = new PDO('sqlite:' . $dbPath, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT            => 5,
    ]);

    // Enable WAL mode for better concurrency
    $pdo->exec('PRAGMA journal_mode = WAL;');
    $pdo->exec('PRAGMA synchronous = NORMAL;');

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            serial_number TEXT NOT NULL UNIQUE,
            os_version TEXT,
            total_ram_mb INTEGER DEFAULT 0,
            agent_version TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");

    $stmt = $pdo->prepare("
        INSERT INTO endpoints (hostname, serial_number, os_version, total_ram_mb, agent_version, last_seen)
        VALUES (:hostname, :serial_number, :os_version, :total_ram_mb, :agent_version, CURRENT_TIMESTAMP)
        ON CONFLICT(serial_number) DO UPDATE SET
            hostname      = excluded.hostname,
            os_version    = excluded.os_version,
            total_ram_mb  = excluded.total_ram_mb,
            agent_version = excluded.agent_version,
            last_seen     = CURRENT_TIMESTAMP
    ");

    $stmt->execute([
        ':hostname'      => substr(trim((string)$data['hostname']), 0, 128),
        ':serial_number' => substr(trim((string)$data['serial_number']), 0, 128),
        ':os_version'    => substr(trim((string)($data['os_version'] ?? 'Unknown')), 0, 64),
        ':total_ram_mb'  => max(0, (int)($data['total_ram_mb'] ?? 0)),
        ':agent_version' => substr(trim((string)($data['agent_version'] ?? '1.1.0')), 0, 32),
    ]);

    echo json_encode([
        'status'  => 'ok',
        'message' => 'Endpoint inventory synchronized'
    ]);

} catch (PDOException $e) {
    error_log('Database error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Internal Server Error']);
}