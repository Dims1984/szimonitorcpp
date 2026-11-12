<?php
declare(strict_types=1);

/**
 * szimonitorcpp v1.2.0 - Backend Synchronization Endpoint
 * Production-hardened PHP + SQLite3 inventory receiver
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);
    exit;
}

// Enforce strict environment token configuration
$expectedToken = getenv('SZI_API_TOKEN');
if (!is_string($expectedToken) || strlen($expectedToken) < 16) {
    error_log('Critical: SZI_API_TOKEN environment variable is missing or too short.');
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Server Configuration Error']);
    exit;
}

// Support both standard HTTP_AUTHORIZATION and REDIRECT_HTTP_AUTHORIZATION (FastCGI/PHP-FPM)
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
$expectedHeader = 'Bearer ' . $expectedToken;
if (!hash_equals($expectedHeader, $authHeader)) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

// Read up to 65537 bytes to accurately detect payloads exceeding the 64 KB (65536 bytes) limit
$rawInput = file_get_contents('php://input', false, null, 0, 65537);
if ($rawInput === false || $rawInput === '') {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Empty request body']);
    exit;
}

if (strlen($rawInput) > 65536) {
    http_response_code(413);
    echo json_encode(['status' => 'error', 'message' => 'Payload Too Large (max 64 KB)']);
    exit;
}

$data = json_decode($rawInput, true, 8);
if (
    !is_array($data) ||
    !isset($data['hostname'], $data['hardware_id']) ||
    !is_string($data['hostname']) ||
    !is_string($data['hardware_id']) ||
    trim($data['hostname']) === '' ||
    trim($data['hardware_id']) === ''
) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid JSON schema or missing required string fields']);
    exit;
}

$machineGuid  = (isset($data['machine_guid']) && is_string($data['machine_guid'])) ? trim($data['machine_guid']) : 'UNKNOWN';
$osVersion    = (isset($data['os_version']) && is_string($data['os_version'])) ? trim($data['os_version']) : 'Unknown';
$agentVersion = (isset($data['agent_version']) && is_string($data['agent_version'])) ? trim($data['agent_version']) : '1.2.0';
$totalRamMb   = (isset($data['total_ram_mb']) && is_int($data['total_ram_mb']) && $data['total_ram_mb'] > 0 && $data['total_ram_mb'] <= 16777216)
    ? $data['total_ram_mb']
    : 0;

// Store SQLite database outside the public web root by default (or use SZI_DB_PATH env var)
$dbPath = getenv('SZI_DB_PATH');
if (!is_string($dbPath) || trim($dbPath) === '') {
    $dbPath = dirname(__DIR__) . '/storage/inventory.db';
}

try {
    $pdo = new PDO('sqlite:' . $dbPath, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT            => 5,
    ]);

    $pdo->exec('PRAGMA journal_mode = WAL;');
    $pdo->exec('PRAGMA synchronous = NORMAL;');

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            hardware_id TEXT NOT NULL UNIQUE,
            machine_guid TEXT,
            os_version TEXT,
            total_ram_mb INTEGER DEFAULT 0,
            agent_version TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen);
    ");

    $stmt = $pdo->prepare("
        INSERT INTO endpoints (hostname, hardware_id, machine_guid, os_version, total_ram_mb, agent_version, last_seen)
        VALUES (:hostname, :hardware_id, :machine_guid, :os_version, :total_ram_mb, :agent_version, CURRENT_TIMESTAMP)
        ON CONFLICT(hardware_id) DO UPDATE SET
            hostname      = excluded.hostname,
            machine_guid  = excluded.machine_guid,
            os_version    = excluded.os_version,
            total_ram_mb  = excluded.total_ram_mb,
            agent_version = excluded.agent_version,
            last_seen     = CURRENT_TIMESTAMP
    ");

    $stmt->execute([
        ':hostname'      => substr(trim($data['hostname']), 0, 128),
        ':hardware_id'   => substr(trim($data['hardware_id']), 0, 128),
        ':machine_guid'  => substr($machineGuid, 0, 128),
        ':os_version'    => substr($osVersion, 0, 64),
        ':total_ram_mb'  => $totalRamMb,
        ':agent_version' => substr($agentVersion, 0, 32),
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
