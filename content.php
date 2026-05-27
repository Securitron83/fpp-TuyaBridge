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

    <!-- DPS Inspector -->
    <div class="card card-outline card-info mt-3">
        <div class="card-header">
            <h3 class="card-title"><i class="fas fa-search"></i> DPS Inspector</h3>
            <div class="card-tools">
                <button type="button" class="btn btn-tool" data-card-widget="collapse">
                    <i class="fas fa-minus"></i>
                </button>
            </div>
        </div>
        <div class="card-body">
            <p class="text-muted small mb-3">
                Query a device live to discover its datapoint IDs, current values, and types.
                Assign friendly names, then save them to <code>devices.conf</code> so they appear
                in the <em>Send DPS</em> dropdown below.
            </p>
            <div class="form-group row mb-2">
                <label class="col-sm-2 col-form-label col-form-label-sm"><strong>Device</strong></label>
                <div class="col-sm-10">
                    <select id="dpsInspectorDevice" class="form-control form-control-sm" style="max-width:260px;display:inline-block">
                        <option value="">— select device —</option>
                    </select>
                    <button class="btn btn-info btn-sm ml-2" onclick="queryDpsDevice()">
                        <i class="fas fa-search"></i> Query Device
                    </button>
                    <span id="dpsQueryStatus" class="text-muted small ml-2"></span>
                </div>
            </div>
            <div id="dpsResultsSection" style="display:none">
                <table class="table table-sm table-bordered table-hover mt-2" style="max-width:680px">
                    <thead class="thead-light">
                        <tr>
                            <th style="width:80px">DPS ID</th>
                            <th style="width:130px">Current Value</th>
                            <th style="width:80px">Type</th>
                            <th>Friendly Name</th>
                        </tr>
                    </thead>
                    <tbody id="dpsResultsBody"></tbody>
                </table>
                <button class="btn btn-success btn-sm" onclick="saveDpsDefs()">
                    <i class="fas fa-save"></i> Save Definitions to Config
                </button>
                <span class="text-muted small ml-2">Saves names to devices.conf; no fppd restart needed for the Send DPS panel.</span>
            </div>
        </div>
    </div>

    <!-- Send DPS (live test from browser) -->
    <div class="card card-outline card-warning mt-3">
        <div class="card-header">
            <h3 class="card-title"><i class="fas fa-paper-plane"></i> Send DPS</h3>
            <div class="card-tools">
                <button type="button" class="btn btn-tool" data-card-widget="collapse">
                    <i class="fas fa-minus"></i>
                </button>
            </div>
        </div>
        <div class="card-body">
            <p class="text-muted small mb-3">
                Send a DPS command directly from the browser for quick testing.
                Use the Inspector above to discover DPS IDs and save friendly names.
            </p>
            <div class="form-group row mb-2">
                <label class="col-sm-2 col-form-label col-form-label-sm"><strong>Device</strong></label>
                <div class="col-sm-10">
                    <select id="sendDpsDevice" class="form-control form-control-sm" style="max-width:260px" onchange="onSendDpsDeviceChange()">
                        <option value="">— select device —</option>
                    </select>
                </div>
            </div>
            <div class="form-group row mb-2">
                <label class="col-sm-2 col-form-label col-form-label-sm"><strong>DPS</strong></label>
                <div class="col-sm-10">
                    <select id="sendDpsKey" class="form-control form-control-sm mb-1" style="max-width:260px">
                        <option value="">— select named DPS —</option>
                    </select>
                    <input type="text" id="sendDpsKeyText" class="form-control form-control-sm" style="max-width:260px"
                           placeholder="…or type DPS ID directly (e.g. 1, 3, 15)">
                </div>
            </div>
            <div class="form-group row mb-2">
                <label class="col-sm-2 col-form-label col-form-label-sm"><strong>Value</strong></label>
                <div class="col-sm-10">
                    <input type="text" id="sendDpsValue" class="form-control form-control-sm" style="max-width:260px"
                           placeholder="true / false / 1 / 2 / 3 …">
                </div>
            </div>
            <div class="form-group row">
                <div class="col-sm-10 offset-sm-2">
                    <button class="btn btn-warning btn-sm" onclick="sendDpsCommand()">
                        <i class="fas fa-paper-plane"></i> Send
                    </button>
                    <span id="sendDpsStatus" class="ml-2 small"></span>
                </div>
            </div>
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

// ---------------------------------------------------------------------------
// DPS Inspector
// ---------------------------------------------------------------------------

function populateDeviceDropdowns() {
    const opts = '<option value="">— select device —</option>' +
        devices.map(d => `<option value="${escapeHtml(d.name || '')}">${escapeHtml(d.name || '')}</option>`).join('');
    $('#dpsInspectorDevice, #sendDpsDevice').html(opts);
    onSendDpsDeviceChange();
}

function queryDpsDevice() {
    const name = $('#dpsInspectorDevice').val();
    if (!name) { alert('Select a device first.'); return; }

    $('#dpsQueryStatus').text('Querying…');
    $('#dpsResultsSection').hide();

    // Pull any previously saved DPS names for pre-filling the name column
    const dev = devices.find(d => d.name === name) || {};
    const savedDps = dev.dps || [];

    $.post(PLUGIN_API + '&command=queryDevice', { name: name }, function(r) {
        refreshLog();
        if (r.error) {
            $('#dpsQueryStatus').html('<span class="text-danger">' + escapeHtml(r.error) + '</span>');
            return;
        }

        let rows = '';
        Object.entries(r.dps).sort((a, b) => Number(a[0]) - Number(b[0])).forEach(([id, val]) => {
            const type    = typeof val === 'boolean' ? 'boolean'
                          : typeof val === 'number'  ? 'integer' : 'string';
            const badge   = type === 'boolean' ? 'badge-primary'
                          : type === 'integer' ? 'badge-success' : 'badge-secondary';
            const display = String(val);
            const saved   = savedDps.find(s => s.id === id);
            const name_   = saved ? escapeHtml(saved.name) : '';
            rows += `<tr>
                <td><code>${escapeHtml(id)}</code></td>
                <td><code>${escapeHtml(display)}</code></td>
                <td><span class="badge ${badge}">${type}</span></td>
                <td><input type="text" class="form-control form-control-sm dps-name-input"
                           data-dps-id="${escapeHtml(id)}" value="${name_}"
                           placeholder="e.g. Power, Light, Fan Speed"></td>
            </tr>`;
        });

        $('#dpsResultsBody').html(rows);
        $('#dpsResultsSection').show();
        $('#dpsQueryStatus').html('<span class="text-success">Found ' + Object.keys(r.dps).length + ' DPS value(s).</span>');
    }, 'json').fail(function(xhr) {
        $('#dpsQueryStatus').html('<span class="text-danger">Request failed — check the log for details.</span>');
        console.error('queryDevice error:', xhr.status, xhr.responseText);
    });
}

function saveDpsDefs() {
    const name = $('#dpsInspectorDevice').val();
    if (!name) return;

    const dpsArray = [];
    $('.dps-name-input').each(function() {
        dpsArray.push({ id: $(this).data('dps-id'), name: $(this).val().trim() });
    });

    $.post(PLUGIN_API + '&command=saveDpsDefs', { name: name, dps: JSON.stringify(dpsArray) }, function(r) {
        if (r.error) {
            $.jGrowl('Save failed: ' + r.error, { theme: 'danger' });
            return;
        }
        $.jGrowl('DPS definitions saved for ' + escapeHtml(name), { theme: 'success' });
        // Update local devices array so Send DPS dropdown refreshes immediately
        const dev = devices.find(d => d.name === name);
        if (dev) dev.dps = dpsArray;
        onSendDpsDeviceChange();
    }, 'json').fail(function() {
        $.jGrowl('Failed to save DPS definitions.', { theme: 'danger' });
    });
}

// ---------------------------------------------------------------------------
// Send DPS (browser-side test)
// ---------------------------------------------------------------------------

function onSendDpsDeviceChange() {
    const name = $('#sendDpsDevice').val();
    if (!name) {
        $('#sendDpsKey').html('<option value="">— select named DPS —</option>');
        return;
    }
    const dev    = devices.find(d => d.name === name) || {};
    const saved  = dev.dps || [];
    let opts = '<option value="">— select named DPS —</option>';
    if (saved.length > 0) {
        saved.forEach(dp => {
            const label = dp.name ? `${dp.id} — ${dp.name}` : dp.id;
            opts += `<option value="${escapeHtml(dp.id)}">${escapeHtml(label)}</option>`;
        });
    } else {
        opts += '<option disabled>(no saved DPS defs — use Inspector above to discover &amp; name them)</option>';
    }
    $('#sendDpsKey').html(opts);
}

function sendDpsCommand() {
    const name  = $('#sendDpsDevice').val();
    const keyDd = $('#sendDpsKey').val();
    const keyTx = $('#sendDpsKeyText').val().trim();
    const key   = keyDd || keyTx;
    const value = $('#sendDpsValue').val().trim();

    if (!name)  { alert('Select a device.'); return; }
    if (!key)   { alert('Select a DPS from the dropdown or type an ID.'); return; }
    if (value === '') { alert('Enter a value.'); return; }

    $('#sendDpsStatus').html('<span class="text-muted">Sending…</span>');

    $.post(PLUGIN_API + '&command=sendDps', { name: name, key: key, value: value }, function(r) {
        if (r.status === 'ok') {
            $('#sendDpsStatus').html('<span class="text-success"><i class="fas fa-check"></i> Sent OK</span>');
        } else {
            const detail = r.detail ? (' — ' + r.detail) : '';
            $('#sendDpsStatus').html('<span class="text-danger">Error (retcode 0x' +
                (r.retcode >>> 0).toString(16).toUpperCase().padStart(8,'0') + detail + ')</span>');
        }
        refreshLog();
    }, 'json').fail(function(xhr) {
        $('#sendDpsStatus').html('<span class="text-danger">Request failed.</span>');
        console.error('sendDps error:', xhr.status, xhr.responseText);
        refreshLog();
    });
}

$(document).ready(function() {
    renderTable();
    loadDebugState();
    populateDeviceDropdowns();
});
</script>
