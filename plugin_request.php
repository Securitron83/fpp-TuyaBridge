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
        $maxLines = min(intval($_GET['lines'] ?? 200), 500);
        header('Content-Type: application/json');
        if (!file_exists($logFile)) {
            echo json_encode(['log' => '(log file not yet created — save a device or send a command first)']);
            break;
        }
        $lines = file($logFile, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            echo json_encode(['log' => '(could not read log file)']);
            break;
        }
        echo json_encode(['log' => implode("\n", array_slice($lines, -$maxLines))]);
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown command']);
        break;
}
