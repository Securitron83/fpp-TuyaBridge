<?php
// fpp-TuyaBridge plugin API handler.
// Invoked by FPP's plugin request proxy:
//   plugin_request.php?plugin=fpp-TuyaBridge&command=<cmd>

$mediaDir    = getenv('FPPDIR_MEDIA') ?: '/home/fpp/media';
$command     = $_POST['command'] ?? $_GET['command'] ?? '';
$devicesFile = $mediaDir . '/plugins/fpp-TuyaBridge/devices.conf';
$logFile     = $mediaDir . '/logs/fpp-TuyaBridge.log';

function tuyaLog($message) {
    global $logFile;
    $ts   = date('Y-m-d H:i:s');
    $line = "[{$ts}] [PHP  ] {$message}" . PHP_EOL;
    @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
}

// ---------------------------------------------------------------------------
// Tuya v3.3 protocol helpers
// ---------------------------------------------------------------------------

// Build a Tuya v3.3 binary packet ready to send over TCP.
// $key: 16-byte local key string
// $payload: plaintext JSON string
// $cmd: command byte (0x07 = SET, 0x0A = QUERY)
// Returns raw binary string or false on AES error.
function tuyaBuildPacket33($key, $payload, $cmd, $seq = 1) {
    // Manual PKCS7 padding to 16-byte boundary
    $padLen = 16 - (strlen($payload) % 16);
    $padded = $payload . str_repeat(chr($padLen), $padLen);

    $encrypted = openssl_encrypt($padded, 'AES-128-ECB', $key,
                                  OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    if ($encrypted === false) return false;

    // Version header: "3.3" + 12 null bytes = 15 bytes
    $ver33  = "3.3" . str_repeat("\x00", 12);
    $length = 15 + strlen($encrypted) + 8; // ver33 + data + CRC(4) + SUFFIX(4)

    $pkt  = "\x00\x00\x55\xaa";
    $pkt .= pack('N', $seq);
    $pkt .= pack('N', $cmd);
    $pkt .= pack('N', $length);
    $pkt .= $ver33;
    $pkt .= $encrypted;
    $pkt .= hex2bin(hash('crc32b', $pkt));  // CRC over everything so far
    $pkt .= "\x00\x00\xaa\x55";
    return $pkt;
}

// Parse and decrypt a Tuya v3.3 response packet.
// Returns plaintext JSON string or null on failure.
function tuyaDecodeResponse33($resp, $key) {
    if (strlen($resp) < 28) return null;
    if (substr($resp, 0, 4) !== "\x00\x00\x55\xaa") return null;

    $length = unpack('N', substr($resp, 12, 4))[1];
    if (strlen($resp) < 16 + $length) return null;

    // Skip retcode (4 bytes at offset 16)
    $dataStart = 20;
    $dataLen   = $length - 12; // minus retcode(4) + CRC(4) + SUFFIX(4)
    if ($dataLen <= 0) return null;

    // Skip version header if present
    if ($dataLen >= 15 && substr($resp, $dataStart, 3) === '3.3') {
        $dataStart += 15;
        $dataLen   -= 15;
    }
    if ($dataLen <= 0) return null;

    $encData = substr($resp, $dataStart, $dataLen);
    $plain   = openssl_decrypt($encData, 'AES-128-ECB', $key,
                                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    if ($plain === false) return null;

    // Remove PKCS7 padding
    $padByte = ord(substr($plain, -1));
    if ($padByte >= 1 && $padByte <= 16) $plain = substr($plain, 0, -$padByte);

    // Strip non-printable bytes so json_decode never fails on stray binary
    return preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '', $plain);
}

// Open a TCP connection to a Tuya device, drain the greeting packet, and
// return the socket resource.  Returns null on failure.
// The returned socket has a 3-second read/write timeout set.
function tuyaConnect($ip) {
    $sock = @fsockopen($ip, 6668, $errno, $errstr, 3);
    if (!$sock) return null;

    // Drain greeting: most devices send a STATUS packet immediately on connect.
    // Use a short 300 ms window so we don't block long if no greeting is sent.
    stream_set_timeout($sock, 0, 300000);
    @fread($sock, 512);

    stream_set_timeout($sock, 3);
    return $sock;
}

// Look up a device entry from devices.conf by name.
// Returns the device array (assoc) or null if not found.
function tuyaFindDevice($devicesFile, $name) {
    if (!file_exists($devicesFile)) return null;
    $devs = json_decode(file_get_contents($devicesFile), true);
    if (!is_array($devs)) return null;
    foreach ($devs as $d) {
        if (($d['name'] ?? '') === $name) return $d;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

switch ($command) {

    case 'saveDevices':
        $data = $_POST['data'] ?? '';
        tuyaLog("saveDevices called, payload length=" . strlen($data));

        // Validate: must decode to a JSON array
        $decoded = json_decode($data, true);
        if (!is_array($decoded)) {
            $jsonErr = json_last_error_msg();
            tuyaLog("saveDevices ERROR: payload is not a valid JSON array: {$jsonErr}");
            http_response_code(400);
            echo json_encode(['error' => 'Invalid JSON array']);
            exit;
        }

        // Ensure the plugin directory exists before writing
        $dir = dirname($devicesFile);
        if (!is_dir($dir)) {
            tuyaLog("saveDevices: creating directory {$dir}");
            if (!mkdir($dir, 0755, true)) {
                $mkdirErr = error_get_last();
                $mkdirMsg = $mkdirErr ? $mkdirErr['message'] : 'unknown';
                tuyaLog("saveDevices ERROR: could not create directory {$dir}: {$mkdirMsg}");
                http_response_code(500);
                echo json_encode(['error' => 'Could not create plugin directory']);
                exit;
            }
        }

        // Re-encode with pretty-print so devices.conf is human-readable JSON.
        // file_put_contents creates the file if it does not yet exist.
        $pretty = json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (file_put_contents($devicesFile, $pretty) === false) {
            $writeErr = error_get_last();
            $writeMsg = $writeErr ? $writeErr['message'] : 'unknown';
            tuyaLog("saveDevices ERROR: could not write {$devicesFile}: {$writeMsg}");
            tuyaLog("saveDevices: file owner=" . (file_exists($devicesFile) ? posix_getpwuid(fileowner($devicesFile))['name'] : 'n/a')
                    . " php_user=" . get_current_user()
                    . " euid=" . posix_geteuid());
            http_response_code(500);
            echo json_encode(['error' => 'Could not write devices.conf']);
            exit;
        }
        tuyaLog("saveDevices: wrote " . count($decoded) . " device(s) to {$devicesFile}");
        echo json_encode(['status' => 'ok']);
        break;

    case 'getDeviceNames':
        // Returns a JSON array of device name strings for FPP command dropdowns.
        $names = [];
        if (file_exists($devicesFile)) {
            $raw  = file_get_contents($devicesFile);
            $devs = json_decode($raw, true);
            if (!is_array($devs)) {
                tuyaLog("getDeviceNames ERROR: could not parse devices.conf: " . json_last_error_msg());
            } else {
                foreach ($devs as $d) {
                    if (!empty($d['name'])) $names[] = $d['name'];
                }
            }
        }
        header('Content-Type: application/json');
        echo json_encode($names);
        break;

    case 'getDebugState':
        $flagFile = $mediaDir . '/plugins/fpp-TuyaBridge/debug.flag';
        header('Content-Type: application/json');
        echo json_encode(['debug' => file_exists($flagFile)]);
        break;

    case 'toggleDebug':
        $flagFile = $mediaDir . '/plugins/fpp-TuyaBridge/debug.flag';
        header('Content-Type: application/json');
        if (file_exists($flagFile)) {
            unlink($flagFile);
            tuyaLog("Debug mode disabled via UI");
            echo json_encode(['debug' => false]);
        } else {
            touch($flagFile);
            tuyaLog("Debug mode enabled via UI");
            echo json_encode(['debug' => true]);
        }
        break;

    case 'getLog':
        $maxLines  = min(intval($_GET['lines'] ?? 200), 500);
        $flagFile  = $mediaDir . '/plugins/fpp-TuyaBridge/debug.flag';
        $soFile    = $mediaDir . '/plugins/fpp-TuyaBridge/libfpp-TuyaBridge.so';
        $debugOn   = file_exists($flagFile);
        $soExists  = file_exists($soFile);

        // Always prepend a status block so the user can see diagnostics
        // even when the log file is empty or missing.
        $status  = "=== Tuya Bridge Plugin Status ===\n";
        $status .= "Plugin .so : " . ($soExists  ? "OK"                        : "NOT FOUND (build failed?)") . "\n";
        $status .= "Debug mode : " . ($debugOn   ? "ENABLED"                   : "DISABLED — tick the checkbox to enable") . "\n";
        $status .= "Log file   : " . (file_exists($logFile)
                        ? "exists (" . number_format(filesize($logFile)) . " bytes)"
                        : "not yet created") . "\n";
        $status .= "=================================\n";

        $logText = '';
        if (file_exists($logFile)) {
            $lines = file($logFile, FILE_IGNORE_NEW_LINES);
            if ($lines !== false) {
                $logText = implode("\n", array_slice($lines, -$maxLines));
            } else {
                $logText = '(could not read log file — check permissions)';
            }
        }

        // Strip non-printable / non-UTF-8 bytes so json_encode never returns false.
        // Old log files may contain binary AES output from a previous bug.
        $logText = preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '?', $logText);

        header('Content-Type: application/json');
        echo json_encode(['log' => $status . $logText]);
        break;

    // -----------------------------------------------------------------------
    // DPS discovery: query a device live and return its current DPS map.
    // POST: name  (device name from devices.conf)
    // -----------------------------------------------------------------------
    case 'queryDevice':
        $deviceName = trim($_POST['name'] ?? '');

        $dev = tuyaFindDevice($devicesFile, $deviceName);
        if (!$dev) {
            http_response_code(400);
            echo json_encode(['error' => "Device not found: {$deviceName}"]);
            exit;
        }

        $ip      = $dev['ip']      ?? '';
        $id      = $dev['id']      ?? '';
        $key     = $dev['key']     ?? '';
        $version = $dev['version'] ?? '3.3';

        if (empty($ip) || empty($id) || strlen($key) !== 16) {
            http_response_code(400);
            echo json_encode(['error' => 'Device entry is missing ip, id, or has an invalid key']);
            exit;
        }

        if ($version !== '3.3') {
            // v3.1 query would need a different packet format; not implemented yet.
            http_response_code(400);
            echo json_encode(['error' => 'queryDevice only supports v3.3 devices']);
            exit;
        }

        // Build CMD_QUERY (0x0A) payload — same structure as SET but no "dps" field
        $ts      = (string)time();
        $payload = '{"devId":' . json_encode($id) . ',"uid":' . json_encode($id) . ',"t":' . json_encode($ts) . '}';

        $pkt = tuyaBuildPacket33($key, $payload, 0x0A);
        if ($pkt === false) {
            echo json_encode(['error' => 'AES encryption failed: ' . openssl_error_string()]);
            exit;
        }

        $sock = tuyaConnect($ip);
        if (!$sock) {
            tuyaLog("queryDevice: connect to {$ip}:6668 failed for '{$deviceName}'");
            echo json_encode(['error' => "Cannot connect to {$ip}:6668 — is the device online?"]);
            exit;
        }

        fwrite($sock, $pkt);
        $resp = @fread($sock, 4096);
        fclose($sock);

        tuyaLog("queryDevice: '{$deviceName}' ({$ip}) — sent " . strlen($pkt) . " B, got " . strlen($resp) . " B");

        $plain = tuyaDecodeResponse33($resp, $key);
        if ($plain === null) {
            echo json_encode(['error' => 'Could not decode response (wrong key? device offline?)']);
            exit;
        }

        $decoded = json_decode($plain, true);
        if (!is_array($decoded)) {
            echo json_encode(['error' => 'Cannot parse response JSON', 'raw' => $plain]);
            exit;
        }

        $dps = $decoded['dps'] ?? $decoded;
        tuyaLog("queryDevice: '{$deviceName}' returned " . count($dps) . " DPS value(s)");

        header('Content-Type: application/json');
        echo json_encode(['status' => 'ok', 'dps' => $dps]);
        break;

    // -----------------------------------------------------------------------
    // Save DPS name definitions for a device into devices.conf.
    // POST: name  (device name)
    //       dps   (JSON array of {id, name} objects)
    // -----------------------------------------------------------------------
    case 'saveDpsDefs':
        $deviceName = trim($_POST['name'] ?? '');
        $dpsJson    = $_POST['dps']  ?? '';

        if (empty($deviceName)) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing device name']);
            exit;
        }

        $dpsArray = json_decode($dpsJson, true);
        if (!is_array($dpsArray)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid DPS JSON array']);
            exit;
        }

        if (!file_exists($devicesFile)) {
            http_response_code(400);
            echo json_encode(['error' => 'devices.conf not found — save devices first']);
            exit;
        }

        $devs = json_decode(file_get_contents($devicesFile), true);
        if (!is_array($devs)) {
            http_response_code(500);
            echo json_encode(['error' => 'Cannot parse devices.conf']);
            exit;
        }

        $found = false;
        foreach ($devs as &$d) {
            if (($d['name'] ?? '') === $deviceName) {
                // Store only non-empty entries; keep array clean
                $d['dps'] = array_values(array_filter($dpsArray, fn($e) => !empty($e['id'])));
                $found    = true;
                break;
            }
        }
        unset($d);

        if (!$found) {
            http_response_code(400);
            echo json_encode(['error' => "Device not found: {$deviceName}"]);
            exit;
        }

        $pretty = json_encode($devs, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (file_put_contents($devicesFile, $pretty) === false) {
            http_response_code(500);
            echo json_encode(['error' => 'Could not write devices.conf']);
            exit;
        }

        tuyaLog("saveDpsDefs: saved " . count($dpsArray) . " DPS definition(s) for '{$deviceName}'");
        echo json_encode(['status' => 'ok']);
        break;

    // -----------------------------------------------------------------------
    // Send a DPS command directly to a device (for UI testing).
    // POST: name   (device name)
    //       key    (DPS ID, e.g. "1", "15")
    //       value  (true/false/on/off, integer, or string)
    // -----------------------------------------------------------------------
    case 'sendDps':
        $deviceName = trim($_POST['name']  ?? '');
        $dpsKey     = trim($_POST['key']   ?? '');
        $dpsValue   = $_POST['value'] ?? '';

        if (empty($deviceName) || empty($dpsKey) || $dpsValue === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Missing name, key, or value']);
            exit;
        }

        $dev = tuyaFindDevice($devicesFile, $deviceName);
        if (!$dev) {
            http_response_code(400);
            echo json_encode(['error' => "Device not found: {$deviceName}"]);
            exit;
        }

        $ip      = $dev['ip']      ?? '';
        $id      = $dev['id']      ?? '';
        $key     = $dev['key']     ?? '';
        $version = $dev['version'] ?? '3.3';

        if (empty($ip) || empty($id) || strlen($key) !== 16) {
            http_response_code(400);
            echo json_encode(['error' => 'Device entry is missing ip, id, or has an invalid key']);
            exit;
        }

        if ($version !== '3.3') {
            http_response_code(400);
            echo json_encode(['error' => 'sendDps only supports v3.3 devices from the UI']);
            exit;
        }

        // Parse value: true/on → bool, false/off → bool, digit-only → int, else string
        if ($dpsValue === 'true'  || $dpsValue === 'on')  $jsonVal = true;
        elseif ($dpsValue === 'false' || $dpsValue === 'off') $jsonVal = false;
        elseif (preg_match('/^-?\d+$/', $dpsValue))           $jsonVal = (int)$dpsValue;
        else                                                   $jsonVal = $dpsValue;

        $dps = [$dpsKey => $jsonVal];

        $ts      = (string)time();
        $payload = '{"devId":' . json_encode($id)
                 . ',"uid":'   . json_encode($id)
                 . ',"t":'     . json_encode($ts)
                 . ',"dps":'   . json_encode($dps, JSON_UNESCAPED_SLASHES) . '}';

        $pkt = tuyaBuildPacket33($key, $payload, 0x07);
        if ($pkt === false) {
            echo json_encode(['error' => 'AES encryption failed: ' . openssl_error_string()]);
            exit;
        }

        $sock = tuyaConnect($ip);
        if (!$sock) {
            tuyaLog("sendDps: connect to {$ip}:6668 failed for '{$deviceName}'");
            echo json_encode(['error' => "Cannot connect to {$ip}:6668 — is the device online?"]);
            exit;
        }

        fwrite($sock, $pkt);
        $resp = @fread($sock, 1024);
        fclose($sock);

        // Decode response to surface any device-reported errors
        $plain   = tuyaDecodeResponse33($resp, $key);
        $retcode = (strlen($resp) >= 20) ? unpack('N', substr($resp, 16, 4))[1] : 0xFFFFFFFF;

        tuyaLog("sendDps: '{$deviceName}' dps={$dpsKey} val={$dpsValue} retcode=0x" . sprintf('%08X', $retcode));

        header('Content-Type: application/json');
        if ($retcode === 0) {
            echo json_encode(['status' => 'ok']);
        } else {
            $msg = ($plain !== null && !empty($plain)) ? $plain : 'non-zero retcode';
            echo json_encode(['status' => 'error', 'retcode' => $retcode, 'detail' => $msg]);
        }
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown command']);
        break;
}
