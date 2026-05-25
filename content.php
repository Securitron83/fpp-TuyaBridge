<?php
$devicesFile = "/home/fpp/media/plugins/fpp-TuyaBridge/devices.conf";

$currentDevices = "[]";
if (file_exists($devicesFile)) {
    $raw = file_get_contents($devicesFile);
    $currentDevices = (empty($raw)) ? "[]" : $raw;
}
?>

<div class="container-fluid">
    <div class="card card-outline card-primary">
        <div class="card-header">
            <h3 class="card-title"><i class="fas fa-plug"></i> Tuya Bridge — Device Management</h3>
        </div>
        <div class="card-body">
            <p class="text-muted small mb-2">
                Devices configured here are available as targets in FPP commands
                (<em>Tuya Bridge - Set Switch</em>, <em>Set Dimmer</em>, <em>Set Color</em>, <em>Send DPS</em>)
                usable from sequences, scripts, and playlist entries.
                After saving, restart fppd from the FPP Status page to apply changes.
            </p>
            <table class="table table-hover table-striped table-sm">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP Address</th>
                        <th>Device ID</th>
                        <th>Local Key</th>
                        <th>Version</th>
                        <th>Type</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="deviceList"></tbody>
            </table>
        </div>
        <div class="card-footer">
            <button class="btn btn-success btn-sm" onclick="addRow()">
                <i class="fas fa-plus"></i> Add Device
            </button>
            <button class="btn btn-primary btn-sm float-right" onclick="saveDevices()">
                <i class="fas fa-save"></i> Save
            </button>
        </div>
    </div>
</div>

<script>
let devices = <?php echo htmlspecialchars_decode($currentDevices, ENT_NOQUOTES); ?>;

const VERSIONS = ['3.3', '3.1'];
const TYPES    = ['switch', 'dimmer', 'rgblight', 'generic'];

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
        .replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function selectOptions(choices, current) {
    return choices.map(c =>
        `<option value="${escapeHtml(c)}" ${c === current ? 'selected' : ''}>${escapeHtml(c)}</option>`
    ).join('');
}

function renderTable() {
    let html = '';
    devices.forEach((d, i) => {
        html += `<tr>
            <td><input type="text" class="form-control form-control-sm" value="${escapeHtml(d.name || '')}"
                       onchange="setVal(${i},'name',this.value)"></td>
            <td><input type="text" class="form-control form-control-sm" value="${escapeHtml(d.ip || '')}"
                       placeholder="192.168.1.x"
                       onchange="setVal(${i},'ip',this.value)"></td>
            <td><input type="text" class="form-control form-control-sm" value="${escapeHtml(d.id || '')}"
                       onchange="setVal(${i},'id',this.value)"></td>
            <td><input type="password" class="form-control form-control-sm" value="${escapeHtml(d.key || '')}"
                       onchange="setVal(${i},'key',this.value)"></td>
            <td><select class="form-control form-control-sm" onchange="setVal(${i},'version',this.value)">
                    ${selectOptions(VERSIONS, d.version || '3.3')}
                </select></td>
            <td><select class="form-control form-control-sm" onchange="setVal(${i},'type',this.value)">
                    ${selectOptions(TYPES, d.type || 'switch')}
                </select></td>
            <td><button class="btn btn-danger btn-sm" onclick="removeRow(${i})">
                    <i class="fas fa-trash"></i>
                </button></td>
        </tr>`;
    });
    $('#deviceList').html(html);
}

function setVal(i, k, v)  { devices[i][k] = v; }
function addRow()          { devices.push({name:'',ip:'',id:'',key:'',version:'3.3',type:'switch'}); renderTable(); }
function removeRow(i)      { devices.splice(i, 1); renderTable(); }

function saveDevices() {
    $.post(
        'plugin_request.php?plugin=fpp-TuyaBridge&command=saveDevices',
        { data: JSON.stringify(devices) },
        function() {
            $.jGrowl('Devices saved. Restart fppd (FPP Status page) to apply changes.', { theme: 'success' });
        }
    ).fail(function() {
        $.jGrowl('Save failed — check FPP logs.', { theme: 'danger' });
    });
}

$(document).ready(function() { renderTable(); });
</script>
