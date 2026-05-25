<?php
// fpp-TuyaBridge plugin API handler.
// Invoked by FPP's plugin request proxy:
//   plugin_request.php?plugin=fpp-TuyaBridge&command=<cmd>

$command     = $_POST['command'] ?? $_GET['command'] ?? '';
$devicesFile = '/home/fpp/media/plugins/fpp-TuyaBridge/devices.conf';

switch ($command) {

    case 'saveDevices':
        $data = $_POST['data'] ?? '';
        // Validate: must decode to a JSON array
        $decoded = json_decode($data, true);
        if (!is_array($decoded)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid JSON array']);
            exit;
        }
        // Ensure the plugin directory exists before writing
        $dir = dirname($devicesFile);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        // Re-encode with pretty-print so devices.conf is human-readable JSON.
        // file_put_contents creates the file if it does not yet exist.
        $pretty = json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (file_put_contents($devicesFile, $pretty) === false) {
            http_response_code(500);
            echo json_encode(['error' => 'Could not write devices.conf']);
            exit;
        }
        echo json_encode(['status' => 'ok']);
        break;

    case 'getDeviceNames':
        // Returns a JSON array of device name strings for FPP command dropdowns.
        $names = [];
        if (file_exists($devicesFile)) {
            $devs = json_decode(file_get_contents($devicesFile), true);
            if (is_array($devs)) {
                foreach ($devs as $d) {
                    if (!empty($d['name'])) $names[] = $d['name'];
                }
            }
        }
        header('Content-Type: application/json');
        echo json_encode($names);
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown command']);
        break;
}
