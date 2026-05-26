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

    <div class="card card-outline card-secondary mt-3">
        <div class="card-header">
            <h3 class="card-title"><i class="fas fa-bug"></i> Developer Tools</h3>
            <div class="card-tools">
                <button type="button" class="btn btn-tool" data-card-widget="collapse">
                    <i class="fas fa-minus"></i>
                </button>
            </div>
        </div>
        <div class="card-body">
            <div class="row mb-3">
                <div class="col-sm-3"><strong>Debug Logging</strong></div>
                <div class="col-sm-9">
                    <label style="font-weight:normal;cursor:pointer">
                        <input type="checkbox" id="debugToggle" onchange="toggleDebug()">
                        &nbsp;Enable debug logging to
                        <code>/home/fpp/media/logs/fpp-TuyaBridge.log</code>
                    </label>
                    <div class="text-muted" style="font-size:12px;margin-top:4px">
                        Takes effect immediately — no fppd restart needed.
                        Logs every command with device name, DPS payload, and raw packet bytes.
                        When a device is not found, lists all names currently loaded by the plugin.
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-sm-3"><strong>Plugin Log</strong></div>
                <div class="col-sm-9">
                    <div style="margin-bottom:6px">
                        <button class="btn btn-sm btn-secondary" onclick="refreshLog()">
                            <i class="fas fa-sync"></i> Refresh
                        </button>
                        <button class="btn btn-sm btn-default ml-1" onclick="clearLogView()">
                            <i class="fas fa-times"></i> Clear View
                        </button>
                        <span class="text-muted" style="font-size:12px;margin-left:8px">
                            Last 200 lines of fpp-TuyaBridge.log
                        </span>
                    </div>
                    <pre id="pluginLog" style="max-height:320px;overflow-y:auto;background:#1a1a1a;color:#d4d4d4;font-size:11px;padding:10px;border-radius:4px;border:1px solid #444;white-space:pre-wrap;word-break:break-all">(click Refresh to load log)</pre>
                </div>
            </div>
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

const PLUGIN_API = 'plugin.php?plugin=fpp-TuyaBridge&nopage=1&page=plugin_request.php';

function saveDevices() {
    $.post(
        PLUGIN_API + '&command=saveDevices',
        { data: JSON.stringify(devices) },
        function() {
            $.jGrowl('Devices saved. Restart fppd (FPP Status page) to apply changes.', { theme: 'success' });
        }
    ).fail(function(xhr) {
        $.jGrowl('Save failed — check /home/fpp/media/logs/fpp-TuyaBridge.log for details.', { theme: 'danger' });
        console.error('saveDevices error:', xhr.status, xhr.responseText);
    });
}

function toggleDebug() {
    var enabling = $('#debugToggle').is(':checked');
    $.post(PLUGIN_API + '&command=toggleDebug', {}, function(r) {
        $('#debugToggle').prop('checked', r.debug);
        $.jGrowl('Debug logging ' + (r.debug ? 'enabled' : 'disabled'), { theme: 'success' });
        if (r.debug) refreshLog();
    }, 'json').fail(function() {
        $('#debugToggle').prop('checked', !enabling); // revert
        $.jGrowl('Could not toggle debug mode.', { theme: 'danger' });
    });
}

function refreshLog() {
    $.get(PLUGIN_API + '&command=getLog', function(r) {
        $('#pluginLog').text(r.log || '(empty)');
        var el = document.getElementById('pluginLog');
        el.scrollTop = el.scrollHeight;
    }, 'json').fail(function() {
        $('#pluginLog').text('(failed to fetch log)');
    });
}

function clearLogView() {
    $('#pluginLog').text('(cleared — click Refresh to reload)');
}

function loadDebugState() {
    $.get(PLUGIN_API + '&command=getDebugState', function(r) {
        $('#debugToggle').prop('checked', r.debug === true);
    }, 'json');
}

$(document).ready(function() {
    renderTable();
    loadDebugState();
});
</script>
