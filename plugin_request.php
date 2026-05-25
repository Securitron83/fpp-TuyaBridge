<?php
// fpp-TuyaBridge plugin API handler.
// Invoked by FPP's plugin request proxy:
//   plugin_request.php?plugin=fpp-TuyaBridge&command=<cmd>

$command     = $_POST['command'] ?? $_GET['command'] ?? '';
$devicesFile = '/home/fpp/media/plugins/fpp-TuyaBridge/devices.conf';

switch ($command) {

    case 'saveDevices':
        $data = $_POST['data'] ?? '';
        // Basic validation: must be a non-empty JSON array
        $decoded = json_decode($data);
        if (!is_array($decoded)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid JSON array']);
            exit;
        }
        if (file_put_contents($devicesFile, $data) === false) {
            http_response_code(500);
            echo json_encode(['error' => 'Could not write devices.conf']);
            exit;
        }
        // The C++ plugin monitors devices.conf via inotify/FileMonitor and
        // reloads automatically — no service restart needed.
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
