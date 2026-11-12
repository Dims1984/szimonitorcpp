<?php
declare(strict_types=1);

/**
 * szimonitorcpp v1.3.0 - Backend Synchronization Endpoint
 * Production-hardened PHP + SQLite3 inventory receiver with automated schema migration
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);
    exit;
}

$expectedToken = getenv('SZI_API_TOKEN');
if (!is_string($expectedToken) || strlen($expectedToken) < 16) {
    error_log('Critical: SZI_API_TOKEN environment variable is missing or too short.');
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Server Configuration Error']);
    exit;
}

$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
$expectedHeader = 'Bearer ' . $expectedToken;
if (!hash_equals($expectedHeader, $authHeader)) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

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
    !is_string($data['hardware_id'])
) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid JSON schema']);
    exit;
}

$hostname   = trim($data['hostname']);
$hardwareId = strtoupper(trim($data['hardware_id']));

// Strict UUID/GUID format validation (rejects placeholders like UNIDENTIFIED-HWID or all-zeros)
$uuidPattern = '/^(?!00000000-0000-0000-0000-000000000000$)(?!FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF$)\{?[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}?$/i';
if ($hostname === '' || strlen($hostname) > 128 || !preg_match($uuidPattern, $hardwareId)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid hostname or hardware_id UUID format']);
    exit;
}

$systemUuid = (isset($data['system_uuid']) && is_string($data['system_uuid']) && preg_match($uuidPattern, trim($data['system_uuid'])))
    ? strtoupper(trim($data['system_uuid']))
    : '';
$machineGuid = (isset($data['machine_guid']) && is_string($data['machine_guid']) && preg_match($uuidPattern, trim($data['machine_guid'])))
    ? strtoupper(trim($data['machine_guid']))
    : '';

$allowedSources = ['smbios_uuid', 'smbios_uuid_only', 'machine_guid_fallback', 'migrated_v1_1'];
$identitySource = (isset($data['identity_source']) && is_string($data['identity_source']) && in_array($data['identity_source'], $allowedSources, true))
    ? $data['identity_source']
    : 'smbios_uuid';

$osVersion    = (isset($data['os_version']) && is_string($data['os_version'])) ? trim($data['os_version']) : 'Unknown';
$agentVersion = (isset($data['agent_version']) && is_string($data['agent_version'])) ? trim($data['agent_version']) : '1.3.0';
$totalRamMb   = (isset($data['total_ram_mb']) && is_int($data['total_ram_mb']) && $data['total_ram_mb'] > 0 && $data['total_ram_mb'] <= 16777216)
    ? $data['total_ram_mb']
    : 0;

// Resolve database path and ensure it is outside the public web root
$dbPath = getenv('SZI_DB_PATH');
if (!is_string($dbPath) || trim($dbPath) === '') {
    $dbPath = dirname(__DIR__) . '/storage/inventory.db';
}

$dbDir = dirname($dbPath);
if (!is_dir($dbDir)) {
    if (!@mkdir($dbDir, 0750, true) && !is_dir($dbDir)) {
        error_log('Critical: Failed to create SQLite storage directory: ' . $dbDir);
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Storage Initialization Error']);
        exit;
    }
}

$realDbDir   = realpath($dbDir);
$realWebRoot = realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__) ?: __DIR__;
if ($realDbDir === false || strpos($realDbDir, $realWebRoot) === 0 || strpos($realDbDir, __DIR__) === 0) {
    error_log('Security Error: SQLite database directory must reside outside the public web root.');
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Insecure Database Path Configuration']);
    exit;
}

// Automated file migration: if legacy v1.1 DB exists in __DIR__ and new DB does not exist yet, move it safely
$legacyDbPath = __DIR__ . '/inventory.db';
if (!file_exists($dbPath) && file_exists($legacyDbPath)) {
    if (@rename($legacyDbPath, $dbPath)) {
        foreach (['-wal', '-shm'] as $suffix) {
            if (file_exists($legacyDbPath . $suffix)) {
                @rename($legacyDbPath . $suffix, $dbPath . $suffix);
            }
        }
        @chmod($dbPath, 0640);
    }
}

/**
 * Ensures schema is created and automatically migrates legacy v1.1/v1.2 tables without data loss
 */
function ensureSchemaAndMigrate(PDO $pdo): void {
    $tableCheck = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='endpoints'")->fetchColumn();

    if ($tableCheck === false) {
        $pdo->exec("
            CREATE TABLE endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                hardware_id TEXT NOT NULL UNIQUE,
                system_uuid TEXT,
                machine_guid TEXT,
                identity_source TEXT DEFAULT 'smbios_uuid',
                os_version TEXT,
                total_ram_mb INTEGER DEFAULT 0,
                agent_version TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX idx_endpoints_last_seen ON endpoints(last_seen);
        ");
        return;
    }

    $columns = [];
    foreach ($pdo->query("PRAGMA table_info(endpoints)") as $col) {
        $columns[$col['name']] = true;
    }

    // Migrate from v1.1 (serial_number -> hardware_id) preserving all rows
    if (isset($columns['serial_number']) && !isset($columns['hardware_id'])) {
        $pdo->exec('BEGIN IMMEDIATE TRANSACTION;');
        try {
            $hasRam = isset($columns['total_ram_mb']);
            $ramSelect = $hasRam ? 'COALESCE(total_ram_mb, 0)' : '0';

            $pdo->exec("
                CREATE TABLE endpoints_v1_3 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    hardware_id TEXT NOT NULL UNIQUE,
                    system_uuid TEXT,
                    machine_guid TEXT,
                    identity_source TEXT DEFAULT 'migrated_v1_1',
                    os_version TEXT,
                    total_ram_mb INTEGER DEFAULT 0,
                    agent_version TEXT,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                INSERT OR IGNORE INTO endpoints_v1_3 (id, hostname, hardware_id, system_uuid, machine_guid, identity_source, os_version, total_ram_mb, agent_version, last_seen)
                SELECT id, hostname, UPPER(TRIM(serial_number)), '', '', 'migrated_v1_1', os_version, {$ramSelect}, agent_version, last_seen
                FROM endpoints
                WHERE TRIM(serial_number) != '' AND TRIM(serial_number) != 'UNIDENTIFIED-HWID';
                DROP TABLE endpoints;
                ALTER TABLE endpoints_v1_3 RENAME TO endpoints;
                CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen);
            ");
            $pdo->exec('COMMIT;');
            $columns['hardware_id'] = true;
            $columns['system_uuid'] = true;
            $columns['machine_guid'] = true;
            $columns['identity_source'] = true;
            $columns['total_ram_mb'] = true;
        } catch (Throwable $e) {
            $pdo->exec('ROLLBACK;');
            throw $e;
        }
    }

    // Incremental column additions for v1.2 -> v1.3 upgrades
    if (!isset($columns['system_uuid'])) {
        $pdo->exec("ALTER TABLE endpoints ADD COLUMN system_uuid TEXT DEFAULT '';");
    }
    if (!isset($columns['machine_guid'])) {
        $pdo->exec("ALTER TABLE endpoints ADD COLUMN machine_guid TEXT DEFAULT '';");
    }
    if (!isset($columns['identity_source'])) {
        $pdo->exec("ALTER TABLE endpoints ADD COLUMN identity_source TEXT DEFAULT 'smbios_uuid';");
    }
    if (!isset($columns['total_ram_mb'])) {
        $pdo->exec("ALTER TABLE endpoints ADD COLUMN total_ram_mb INTEGER DEFAULT 0;");
    }
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen);");
}

try {
    $pdo = new PDO('sqlite:' . $dbPath, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT            => 5,
    ]);

    $pdo->exec('PRAGMA journal_mode = WAL;');
    $pdo->exec('PRAGMA synchronous = NORMAL;');

    ensureSchemaAndMigrate($pdo);

    $stmt = $pdo->prepare("
        INSERT INTO endpoints (hostname, hardware_id, system_uuid, machine_guid, identity_source, os_version, total_ram_mb, agent_version, last_seen)
        VALUES (:hostname, :hardware_id, :system_uuid, :machine_guid, :identity_source, :os_version, :total_ram_mb, :agent_version, CURRENT_TIMESTAMP)
        ON CONFLICT(hardware_id) DO UPDATE SET
            hostname        = excluded.hostname,
            system_uuid     = CASE WHEN excluded.system_uuid != '' THEN excluded.system_uuid ELSE endpoints.system_uuid END,
            machine_guid    = CASE WHEN excluded.machine_guid != '' THEN excluded.machine_guid ELSE endpoints.machine_guid END,
            identity_source = excluded.identity_source,
            os_version      = excluded.os_version,
            total_ram_mb    = excluded.total_ram_mb,
            agent_version   = excluded.agent_version,
            last_seen       = CURRENT_TIMESTAMP
    ");

    $stmt->execute([
        ':hostname'        => substr($hostname, 0, 128),
        ':hardware_id'     => substr($hardwareId, 0, 64),
        ':system_uuid'     => substr($systemUuid, 0, 64),
        ':machine_guid'    => substr($machineGuid, 0, 64),
        ':identity_source' => $identitySource,
        ':os_version'      => substr($osVersion, 0, 64),
        ':total_ram_mb'    => $totalRamMb,
        ':agent_version'   => substr($agentVersion, 0, 32),
    ]);

    echo json_encode([
        'status'  => 'ok',
        'message' => 'Endpoint inventory synchronized'
    ]);

} catch (Throwable $e) {
    error_log('Database error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Internal Server Error']);
}
