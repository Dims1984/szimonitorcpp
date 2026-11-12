<?php
declare(strict_types=1);

/**
 * szimonitorcpp - Backend Synchronization Endpoint
 * Lightweight PHP + SQLite3 inventory receiver
 */

header('Content-Type: application/json; charset=utf-8');

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);
    exit;
}

// Verify API token via environment variable (safe default fallback for dev)
$expectedToken = getenv('SZI_API_TOKEN') ?: 'YOUR_PUBLIC_PLACEHOLDER_TOKEN';
$authHeader    = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

if ($authHeader !== 'Bearer ' . $expectedToken) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

// Parse incoming JSON payload
$rawInput = file_get_contents('php://input');
$data     = json_decode($rawInput, true);

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
    ]);

    // Ensure schema exists
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            serial_number TEXT NOT NULL UNIQUE,
            os_version TEXT,
            agent_version TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");

    // Upsert endpoint record safely using prepared statements
    $stmt = $pdo->prepare("
        INSERT INTO endpoints (hostname, serial_number, os_version, agent_version, last_seen)
        VALUES (:hostname, :serial_number, :os_version, :agent_version, CURRENT_TIMESTAMP)
        ON CONFLICT(serial_number) DO UPDATE SET
            hostname      = excluded.hostname,
            os_version    = excluded.os_version,
            agent_version = excluded.agent_version,
            last_seen     = CURRENT_TIMESTAMP
    ");

    $stmt->execute([
        ':hostname'      => substr(trim((string)$data['hostname']), 0, 128),
        ':serial_number' => substr(trim((string)$data['serial_number']), 0, 128),
        ':os_version'    => substr(trim((string)($data['os_version'] ?? 'Unknown')), 0, 64),
        ':agent_version' => substr(trim((string)($data['agent_version'] ?? '1.0.0')), 0, 32),
    ]);

    echo json_encode([
        'status'  => 'ok',
        'message' => 'Endpoint inventory updated successfully'
    ]);

} catch (PDOException $e) {
    error_log('Database error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Internal Server Error']);
}