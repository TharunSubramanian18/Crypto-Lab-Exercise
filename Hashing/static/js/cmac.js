document.getElementById('btn-gen').addEventListener('click', function() {
    var b = new Uint8Array(16);
    crypto.getRandomValues(b);
    document.getElementById('key').value = Array.from(b)
        .map(function(x){ return x.toString(16).padStart(2,'0'); }).join('');
});

function printSteps(con, steps, block_summary, last_complete) {
    steps.forEach(function(step) {
        sep(con);
        consoleLine(con, 'c-sec', '>>> ' + step.title);
        if (step.detail) consoleLine(con, 'c-dim', '    ' + step.detail);
        consoleLine(con, '', '');

        if (step.data) {
            step.data.forEach(function(line, i) {
                var cls = (step.title.indexOf('Final') !== -1 && i === step.data.length - 1)
                    ? 'c-res' : 'c-val';
                consoleLine(con, cls, '  ' + line);
            });
        }
    });

    // Block layout section
    sep(con);
    consoleLine(con, 'c-sec', '>>> Block Layout');
    consoleLine(con, '', '');
    block_summary.forEach(function(blk) {
        if (blk.is_incomplete) {
            consoleLine(con, 'c-warn',
                '  [BLOCK ' + blk.index + '] *** INCOMPLETE / PADDED *** (XOR with K2)');
            consoleLine(con, 'c-warn', '  ' + blk.hex);
        } else if (blk.is_last) {
            consoleLine(con, 'c-val',
                '  [BLOCK ' + blk.index + '] complete last block (XOR with K1)');
            consoleLine(con, 'c-val', '  ' + blk.hex);
        } else {
            consoleLine(con, 'c-val',
                '  [BLOCK ' + blk.index + '] full block');
            consoleLine(con, 'c-dim', '  ' + blk.hex);
        }
        consoleLine(con, '', '');
    });

    sep(con);
}

document.getElementById('btn-run').addEventListener('click', async function() {
    var msg = document.getElementById('msg').value;
    var key = document.getElementById('key').value.trim();
    var con = document.getElementById('console');
    var status = document.getElementById('status');
    var title = document.getElementById('console-title');

    consoleClear(con);
    status.className = 'status';
    status.textContent = 'computing...';

    consoleLine(con, 'c-dim', '$ cmac --key ' + key + ' "' + msg + '"');
    consoleLine(con, '', '');

    try {
        var res = await fetch('/api/cmac', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: msg, key: key})
        });
        var data = await res.json();

        if (!data.success) {
            consoleLine(con, 'c-warn', 'ERROR: ' + data.error);
            status.className = 'status err';
            status.textContent = data.error;
            return;
        }

        printSteps(con, data.steps, data.block_summary, data.last_complete);
        consoleLine(con, '', '');
        consoleLine(con, 'c-res', 'CMAC = ' + data.mac);
        consoleLine(con, '', '');

        title.textContent = 'cmac output  [' + data.mac.substring(0,16) + '...]';
        status.className = 'status';
        status.textContent = 'done';
        consoleScroll(con);
    } catch(e) {
        consoleLine(con, 'c-warn', 'ERROR: ' + e.message);
        status.className = 'status err';
        status.textContent = e.message;
    }
});

document.getElementById('btn-clear').addEventListener('click', function() {
    consoleClear(document.getElementById('console'));
    document.getElementById('status').textContent = '';
    document.getElementById('console-title').textContent = 'output';
});

document.getElementById('msg').addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter')
        document.getElementById('btn-run').click();
});
