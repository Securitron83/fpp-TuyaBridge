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

function isDebugEnabled() {
    global $mediaDir;
    return file_exists($mediaDir . '/plugins/fpp-TuyaBridge/debug.flag');
}

function tuyaDebug($message) {
    if (isDebugEnabled()) tuyaLog($message);
}

// Hex-dump a binary string in the same format the C++ plugin uses:
//   XX:XX:XX:XX XX:XX:XX:XX …
function tuyaHex($bin) {
    $hex = '';
    $len = strlen($bin);
    for ($i = 0; $i < $len; $i++) {
        $hex .= sprintf('%02X', ord($bin[$i]));
        $hex .= (($i + 1) % 4 === 0) ? ' ' : ':';
    }
    return rtrim($hex, ': ');
}

// ---------------------------------------------------------------------------
// Tuya v3.3 protocol helpers
// ---------------------------------------------------------------------------

// Build a Tuya v3.3 binary packet ready to send over TCP.
// $key: 16-byte local key string
// $payload: plaintext JSON string
// $cmd: command byte (0x07 = SET, 0x0A = QUERY)
// $ver33: include the 15-byte "3.3" version header (required for SET/0x07,
//         must be omitted for QUERY/0x0A per tinytuya behaviour)
// Returns raw binary string or false on AES error.
function tuyaBuildPacket33($key, $payload, $cmd, $seq = 1, $ver33 = true) {
    // Manual PKCS7 padding to 16-byte boundary
    $padLen = 16 - (strlen($payload) % 16);
    $padded = $payload . str_repeat(chr($padLen), $padLen);

    $encrypted = openssl_encrypt($padded, 'AES-128-ECB', $key,
                                  OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    if ($encrypted === false) return false;

    $header = $ver33 ? ("3.3" . str_repeat("\x00", 12)) : '';
    $length = strlen($header) + strlen($encrypted) + 8; // header + data + CRC(4) + SUFFIX(4)

    $pkt  = "\x00\x00\x55\xaa";
    $pkt .= pack('N', $seq);
    $pkt .= pack('N', $cmd);
    $pkt .= pack('N', $length);
    $pkt .= $header;
    $pkt .= $encrypted;
    $pkt .= hex2bin(hash('crc32b', $pkt));  // CRC over everything so far
    $pkt .= "\x00\x00\xaa\x55";
    return $pkt;
}

// Shared decrypt helper: AES-128-ECB, strip PKCS7 padding, sanitise.
function tuyaAesDecrypt($encData, $key) {
    $plain = openssl_decrypt($encData, 'AES-128-ECB', $key,
                              OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    if ($plain === false) return null;
    $padByte = ord(substr($plain, -1));
    if ($padByte >= 1 && $padByte <= 16) $plain = substr($plain, 0, -$padByte);
    return preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '', $plain);
}

// Parse a Tuya v3.3 RESPONSE packet (reply to a command we sent).
// These packets have: PREFIX(4)+SEQ(4)+CMD(4)+LEN(4)+RETCODE(4)+[VER33]+DATA+CRC(4)+SUFFIX(4)
// Returns [plaintext, retcode] or null on failure.
function tuyaDecodeResponse33($resp, $key) {
    if (strlen($resp) < 28) return null;
    if (substr($resp, 0, 4) !== "\x00\x00\x55\xaa") return null;

    $length = unpack('N', substr($resp, 12, 4))[1];
    if (strlen($resp) < 16 + $length) return null;

    $retcode   = unpack('N', substr($resp, 16, 4))[1];
    $dataStart = 20;
    $dataLen   = $length - 12; // minus retcode(4) + CRC(4) + SUFFIX(4)
    if ($dataLen <= 0) return ['', $retcode];

    if ($dataLen >= 15 && substr($resp, $dataStart, 3) === '3.3') {
        $dataStart += 15;
        $dataLen   -= 15;
    }
    if ($dataLen <= 0) return ['', $retcode];

    $plain = tuyaAesDecrypt(substr($resp, $dataStart, $dataLen), $key);
    return [$plain, $retcode];
}

// Parse a Tuya v3.3 STATUS packet (device-initiated: greeting or query response).
// These packets have: PREFIX(4)+SEQ(4)+CMD(4)+LEN(4)+[VER33]+DATA+CRC(4)+SUFFIX(4)
// No retcode field — the device sends these unsolicited.
// Returns plaintext or null on failure.
function tuyaDecodeStatus33($resp, $key) {
    if (strlen($resp) < 24) return null;
    if (substr($resp, 0, 4) !== "\x00\x00\x55\xaa") return null;

    $length    = unpack('N', substr($resp, 12, 4))[1];
    $dataStart = 16;
    $dataLen   = $length - 8; // minus CRC(4) + SUFFIX(4)
    if ($dataLen <= 0) return null;

    if ($dataLen >= 15 && substr($resp, $dataStart, 3) === '3.3') {
        $dataStart += 15;
        $dataLen   -= 15;
    }
    if ($dataLen <= 0) return null;

    return tuyaAesDecrypt(substr($resp, $dataStart, $dataLen), $key);
}

// Detect packet format by inspecting bytes 16-18 and call the right decoder.
//
// STATUS packets (device-initiated): byte 16-18 == "3.3" (start of VER33 header,
//   no retcode field).  dataStart=16, dataLen=LEN-8.
//
// RESPONSE packets (reply to a command we sent): byte 16-18 is the high bytes of
//   a retcode (always a small integer like 0x00000000 or 0x00000001, never "3.3").
//   dataStart=20, dataLen=LEN-12.
//
// Returns plaintext string or null.
function tuyaPickDecoder($resp, $key) {
    if (strlen($resp) < 24) return null;
    if (substr($resp, 0, 4) !== "\x00\x00\x55\xaa") return null;
    // If bytes 16-18 are "3.3" this is a STATUS packet (no retcode field)
    if (substr($resp, 16, 3) === '3.3') {
        return tuyaDecodeStatus33($resp, $key);
    }
    // Otherwise it is a RESPONSE packet (retcode at bytes 16-19)
    $r = tuyaDecodeResponse33($resp, $key);
    return $r ? $r[0] : null;
}

// ---------------------------------------------------------------------------
// Tuya v3.4 / v3.5 protocol helpers
//
// Both versions negotiate a per-connection session key before any other
// traffic.  v3.4 uses 0x55AA frames with AES-128-ECB + HMAC-SHA256; v3.5 uses
// 0x6699 frames with AES-128-GCM.  Mirrors src/TuyaProtocol.cpp.
// ---------------------------------------------------------------------------

function tuyaUsesSession($version) {
    return $version === '3.4' || $version === '3.5';
}

function tuyaBuildSessionPacket($version, $key, $plaintext, $cmd, $seq) {
    if ($version === '3.5') {
        $iv     = random_bytes(12);
        $header = "\x00\x00\x66\x99" . "\x00\x00" . pack('N', $seq) . pack('N', $cmd)
                . pack('N', 12 + strlen($plaintext) + 16);
        $tag    = '';
        $ct     = openssl_encrypt($plaintext, 'aes-128-gcm', $key, OPENSSL_RAW_DATA,
                                  $iv, $tag, substr($header, 4), 16);
        if ($ct === false) return false;
        return $header . $iv . $ct . $tag . "\x00\x00\x99\x66";
    }
    $padLen = 16 - (strlen($plaintext) % 16);
    $enc    = openssl_encrypt($plaintext . str_repeat(chr($padLen), $padLen), 'AES-128-ECB', $key,
                              OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    if ($enc === false) return false;
    $pkt = "\x00\x00\x55\xaa" . pack('N', $seq) . pack('N', $cmd) . pack('N', strlen($enc) + 36) . $enc;
    return $pkt . hash_hmac('sha256', $pkt, $key, true) . "\x00\x00\xaa\x55";
}

// Decode one frame from the front of $buf.  Returns [frame, bytesConsumed],
// [null, 0] when more data is needed, or false on a malformed/unauthenticated frame.
// frame = ['cmd' => int, 'retcode' => int|null, 'payload' => string]
function tuyaDecodeSessionFrame($version, $key, $buf) {
    if ($version === '3.5') {
        $start = strpos($buf, "\x00\x00\x66\x99");
        if ($start === false || strlen($buf) < $start + 18) return [null, 0];
        $len = unpack('N', substr($buf, $start + 14, 4))[1];
        if ($len < 28) return false;
        if (strlen($buf) < $start + 18 + $len + 4) return [null, 0];
        $aad = substr($buf, $start + 4, 14);
        $iv  = substr($buf, $start + 18, 12);
        $ct  = substr($buf, $start + 30, $len - 28);
        $tag = substr($buf, $start + 18 + $len - 16, 16);
        $pt  = openssl_decrypt($ct, 'aes-128-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if ($pt === false) return false;
        $retcode = null;
        if (strlen($pt) >= 4 && substr($pt, 0, 3) === "\x00\x00\x00") {
            $retcode = ord($pt[3]);
            $pt = substr($pt, 4);
        }
        return [['cmd' => unpack('N', substr($buf, $start + 10, 4))[1],
                 'retcode' => $retcode, 'payload' => $pt], $start + 18 + $len + 4];
    }

    $start = strpos($buf, "\x00\x00\x55\xaa");
    if ($start === false || strlen($buf) < $start + 16) return [null, 0];
    $len = unpack('N', substr($buf, $start + 12, 4))[1];
    if ($len < 36) return false;
    if (strlen($buf) < $start + 16 + $len) return [null, 0];
    $bodyLen = $len - 36;
    $signed  = substr($buf, $start, 16 + $bodyLen);
    $mac     = substr($buf, $start + 16 + $bodyLen, 32);
    if (!hash_equals(hash_hmac('sha256', $signed, $key, true), $mac)) return false;
    $body    = substr($buf, $start + 16, $bodyLen);
    $retcode = null;
    if ($bodyLen % 16 === 4) {
        $retcode = unpack('N', substr($body, 0, 4))[1];
        $body    = substr($body, 4);
    }
    $plain = $body === '' ? '' : openssl_decrypt($body, 'AES-128-ECB', $key,
                                                 OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    if ($plain === false) return false;
    $pad = $plain === '' ? 0 : ord(substr($plain, -1));
    if ($pad >= 1 && $pad <= 16) $plain = substr($plain, 0, -$pad);
    return [['cmd' => unpack('N', substr($buf, $start + 8, 4))[1],
             'retcode' => $retcode, 'payload' => $plain], $start + 16 + $len];
}

// Read frames from $sock until one decodes or the read times out.
function tuyaReadSessionFrame($sock, $version, $key, &$buf) {
    for ($i = 0; $i < 20; $i++) {
        $r = tuyaDecodeSessionFrame($version, $key, $buf);
        if ($r === false) return false;
        if ($r[0] !== null) {
            $buf = substr($buf, $r[1]);
            return $r[0];
        }
        $chunk = @fread($sock, 4096);
        if ($chunk === false || $chunk === '') return false;
        $buf .= $chunk;
    }
    return false;
}

// Connect and negotiate a session key.  Returns ['sock', 'key', 'seq', 'buf'] or a string error.
function tuyaOpenSession($ip, $version, $localKey) {
    $sock = @fsockopen($ip, 6668, $errno, $errstr, 3);
    if (!$sock) return "Cannot connect to {$ip}:6668 — is the device online?";
    stream_set_timeout($sock, 3);

    $localNonce = random_bytes(16);
    $seq = 1;
    $buf = '';
    fwrite($sock, tuyaBuildSessionPacket($version, $localKey, $localNonce, 0x03, $seq++));
    $resp = tuyaReadSessionFrame($sock, $version, $localKey, $buf);
    if (!$resp || $resp['cmd'] !== 0x04) {
        fclose($sock);
        return "No v{$version} session response — wrong key or version?";
    }
    $body = $resp['payload'];
    if (strlen($body) === 52) $body = substr($body, 4);
    if (strlen($body) < 48 ||
        !hash_equals(hash_hmac('sha256', $localNonce, $localKey, true), substr($body, 16, 32))) {
        fclose($sock);
        return 'Session response failed verification — wrong key?';
    }
    $remoteNonce = substr($body, 0, 16);
    fwrite($sock, tuyaBuildSessionPacket($version, $localKey,
           hash_hmac('sha256', $remoteNonce, $localKey, true), 0x05, $seq++));

    $mixed = $localNonce ^ $remoteNonce;
    if ($version === '3.5') {
        $tag = '';
        $sessionKey = openssl_encrypt($mixed, 'aes-128-gcm', $localKey, OPENSSL_RAW_DATA,
                                      substr($localNonce, 0, 12), $tag, '', 16);
    } else {
        $sessionKey = openssl_encrypt($mixed, 'AES-128-ECB', $localKey,
                                      OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }
    if ($sessionKey === false || strlen($sessionKey) !== 16) {
        fclose($sock);
        return 'Session key derivation failed';
    }
    return ['sock' => $sock, 'key' => $sessionKey, 'seq' => $seq, 'buf' => $buf];
}

// Strip the "3.4"/"3.5" + 12-null version header if present.
function tuyaStripVersionHeader($payload, $version) {
    if (strlen($payload) >= 15 && substr($payload, 0, 3) === $version) return substr($payload, 15);
    return $payload;
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

        // Probe whether PHP can write to the log file right now.
        $testLine  = "[" . date('Y-m-d H:i:s') . "] [PHP  ] getLog: write-test OK (php_uid=" . posix_geteuid() . ")\n";
        $canWrite  = (@file_put_contents($logFile, $testLine, FILE_APPEND | LOCK_EX) !== false);

        // Always prepend a status block so the user can see diagnostics
        // even when the log file is empty or missing.
        $status  = "=== Tuya Bridge Plugin Status ===\n";
        $status .= "Plugin .so : " . ($soExists  ? "OK"                        : "NOT FOUND (build failed?)") . "\n";
        $status .= "Debug mode : " . ($debugOn   ? "ENABLED"                   : "DISABLED — tick the checkbox to enable") . "\n";
        $status .= "PHP write  : " . ($canWrite  ? "OK"                        : "FAILED — check log file permissions") . "\n";
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
    // DPS discovery: connect to a device and read the STATUS greeting.
    // Tuya devices broadcast their full DPS state immediately on TCP connect —
    // we read that packet rather than sending CMD_QUERY (which some firmware
    // returns in a different packet format, causing parse errors).
    // POST: name  (device name from devices.conf)
    // -----------------------------------------------------------------------
    case 'queryDevice':
        $deviceName = trim($_POST['name'] ?? '');
        tuyaLog("queryDevice: request for '{$deviceName}'");

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

        if (tuyaUsesSession($version)) {
            $s = tuyaOpenSession($ip, $version, $key);
            if (is_string($s)) {
                tuyaLog("queryDevice: '{$deviceName}' ({$ip}) v{$version}: {$s}");
                echo json_encode(['error' => $s]);
                exit;
            }
            // DP_QUERY_NEW (0x10) with an empty payload; queries carry no version header
            fwrite($s['sock'], tuyaBuildSessionPacket($version, $s['key'], '{}', 0x10, $s['seq']++));
            $plain = null;
            for ($i = 0; $i < 3 && $plain === null; $i++) {
                $f = tuyaReadSessionFrame($s['sock'], $version, $s['key'], $s['buf']);
                if (!$f) break;
                $p = tuyaStripVersionHeader($f['payload'], $version);
                if (strpos($p, '"dps"') !== false) $plain = $p;
            }
            fclose($s['sock']);
            if ($plain === null) {
                tuyaLog("queryDevice: '{$deviceName}' v{$version} — no status reply");
                echo json_encode(['error' => 'Device did not return its status']);
                exit;
            }
            tuyaDebug("tuya/{$deviceName}/query-json  {$plain}");
            $decoded = json_decode($plain, true);
            $dps = $decoded['dps'] ?? ($decoded['data']['dps'] ?? []);
            tuyaLog("queryDevice: '{$deviceName}' returned " . count($dps) . " DPS value(s)");
            header('Content-Type: application/json');
            echo json_encode(['status' => 'ok', 'dps' => $dps]);
            exit;
        }

        if ($version !== '3.3') {
            http_response_code(400);
            echo json_encode(['error' => "queryDevice does not support v{$version} devices"]);
            exit;
        }

        // Connect without draining the greeting.
        $sock = @fsockopen($ip, 6668, $errno, $errstr, 3);
        if (!$sock) {
            tuyaLog("queryDevice: connect to {$ip}:6668 failed for '{$deviceName}': {$errstr}");
            echo json_encode(['error' => "Cannot connect to {$ip}:6668 — is the device online?"]);
            exit;
        }

        $plain = null;

        // Step 1: read greeting with a short 300 ms window.
        // Many devices broadcast their full DPS state immediately on connect.
        stream_set_timeout($sock, 0, 300000);
        $greeting = @fread($sock, 4096);
        if (strlen($greeting) >= 24) {
            tuyaDebug("tuya/{$deviceName}/query-greeting  " . strlen($greeting) . " bytes: " . tuyaHex($greeting));
            $plain = tuyaPickDecoder($greeting, $key);
        }

        // Step 2: if no greeting or decoding failed, send CMD_QUERY (0x0A).
        if ($plain === null || trim($plain) === '') {
            $ts      = (string)time();
            // CMD_QUERY payload includes gwId; NO version header (tinytuya omits
            // VER33 for DP_QUERY — including it causes "parse data error")
            $qpayload = '{"gwId":' . json_encode($id) . ',"devId":' . json_encode($id) . ',"uid":' . json_encode($id) . ',"t":' . json_encode($ts) . '}';
            $pkt = tuyaBuildPacket33($key, $qpayload, 0x0A, 1, false);
            if ($pkt !== false) {
                tuyaDebug("tuya/{$deviceName}/query-tx  " . strlen($pkt) . " bytes: " . tuyaHex($pkt));
                fwrite($sock, $pkt);
                stream_set_timeout($sock, 2);
                $resp = @fread($sock, 4096);
                tuyaLog("queryDevice: '{$deviceName}' ({$ip}) — CMD_QUERY rx " . strlen($resp) . " B");
                tuyaDebug("tuya/{$deviceName}/query-rx  " . strlen($resp) . " bytes: " . tuyaHex($resp));
                $plain = tuyaPickDecoder($resp, $key);
            }
        }

        fclose($sock);

        if ($plain === null || trim($plain) === '') {
            tuyaLog("queryDevice: '{$deviceName}' — could not decode any response");
            echo json_encode(['error' => 'Could not decode response — wrong key, or device did not respond']);
            exit;
        }

        tuyaDebug("tuya/{$deviceName}/query-json  {$plain}");

        $decoded = json_decode($plain, true);
        if (!is_array($decoded)) {
            tuyaLog("queryDevice: '{$deviceName}' — JSON parse failed, raw: {$plain}");
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

        if ($version !== '3.3' && !tuyaUsesSession($version)) {
            http_response_code(400);
            echo json_encode(['error' => "sendDps does not support v{$version} devices from the UI"]);
            exit;
        }

        // Parse value: true/on → bool, false/off → bool, digit-only → int, else string
        if ($dpsValue === 'true'  || $dpsValue === 'on')  $jsonVal = true;
        elseif ($dpsValue === 'false' || $dpsValue === 'off') $jsonVal = false;
        elseif (preg_match('/^-?\d+$/', $dpsValue))           $jsonVal = (int)$dpsValue;
        else                                                   $jsonVal = $dpsValue;

        $dps = [$dpsKey => $jsonVal];

        if (tuyaUsesSession($version)) {
            tuyaLog("sendDps: '{$deviceName}' ip={$ip} v{$version} dps={$dpsKey} val={$dpsValue}");
            $s = tuyaOpenSession($ip, $version, $key);
            if (is_string($s)) {
                tuyaLog("sendDps: '{$deviceName}': {$s}");
                echo json_encode(['error' => $s]);
                exit;
            }
            $payload = '{"protocol":5,"t":' . time() . ',"data":{"dps":'
                     . json_encode($dps, JSON_UNESCAPED_SLASHES) . '}}';
            fwrite($s['sock'], tuyaBuildSessionPacket($version, $s['key'],
                   $version . str_repeat("\x00", 12) . $payload, 0x0D, $s['seq']++));
            $f = tuyaReadSessionFrame($s['sock'], $version, $s['key'], $s['buf']);
            fclose($s['sock']);
            $retcode = $f ? ($f['retcode'] ?? 0) : 0xFFFFFFFF;
            $plain   = $f ? tuyaStripVersionHeader($f['payload'], $version) : '';
            tuyaLog("sendDps: '{$deviceName}' retcode=0x" . sprintf('%08X', $retcode)
                    . ($plain !== '' ? " response: {$plain}" : ''));
            header('Content-Type: application/json');
            echo json_encode($retcode === 0
                ? ['status' => 'ok']
                : ['status' => 'error', 'retcode' => $retcode, 'detail' => $plain ?: 'no response']);
            exit;
        }

        $ts      = (string)time();
        $payload = '{"devId":' . json_encode($id)
                 . ',"uid":'   . json_encode($id)
                 . ',"t":'     . json_encode($ts)
                 . ',"dps":'   . json_encode($dps, JSON_UNESCAPED_SLASHES) . '}';

        tuyaLog("sendDps: '{$deviceName}' ip={$ip} dps={$dpsKey} val={$dpsValue}");
        tuyaLog("sendDps: payload  {$payload}");

        $pkt = tuyaBuildPacket33($key, $payload, 0x07);
        if ($pkt === false) {
            tuyaLog("sendDps: AES encryption failed: " . openssl_error_string());
            echo json_encode(['error' => 'AES encryption failed: ' . openssl_error_string()]);
            exit;
        }

        tuyaDebug("tuya/{$deviceName}/packet  " . strlen($pkt) . " bytes: " . tuyaHex($pkt));

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
        $result  = tuyaDecodeResponse33($resp, $key);
        $plain   = $result ? $result[0] : null;
        $retcode = $result ? $result[1] : (strlen($resp) >= 20 ? unpack('N', substr($resp, 16, 4))[1] : 0xFFFFFFFF);

        tuyaLog("sendDps: '{$deviceName}' retcode=0x" . sprintf('%08X', $retcode) . " (" . ($retcode === 0 ? 'OK' : 'ERROR') . ")");
        if ($plain !== null && $plain !== '')
            tuyaLog("sendDps: '{$deviceName}' response: {$plain}");

        header('Content-Type: application/json');
        if ($retcode === 0) {
            echo json_encode(['status' => 'ok']);
        } else {
            $msg = ($plain !== null && $plain !== '') ? $plain : 'non-zero retcode';
            echo json_encode(['status' => 'error', 'retcode' => $retcode, 'detail' => $msg]);
        }
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown command']);
        break;
}
