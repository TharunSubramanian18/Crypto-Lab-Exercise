function printSteps(con, steps) {
    steps.forEach(function(step) {
        sep(con);
        consoleLine(con, 'c-sec', '>>> ' + step.title);
        if (step.detail) consoleLine(con, 'c-dim', '    ' + step.detail);
        consoleLine(con, '', '');

        // flat data lines
        if (step.data) {
            step.data.forEach(function(line, i) {
                // last data line in final step = the digest
                var cls = (step.title.indexOf('Final') !== -1 && i === step.data.length - 1)
                    ? 'c-res' : 'c-val';
                consoleLine(con, cls, '  ' + line);
            });
        }

        // block substeps
        if (step.block_steps) {
            step.block_steps.forEach(function(bs) {
                consoleLine(con, '', '');
                consoleLine(con, 'c-key', '  -- ' + bs.sub);
                bs.lines.forEach(function(l) {
                    consoleLine(con, 'c-val', '    ' + l);
                });
            });
        }
    });
    sep(con);
}

document.getElementById('btn-run').addEventListener('click', async function() {
    var msg = document.getElementById('msg').value;
    var con = document.getElementById('console');
    var status = document.getElementById('status');
    var title = document.getElementById('console-title');

    consoleClear(con);
    status.className = 'status';
    status.textContent = 'computing...';

    consoleLine(con, 'c-dim', '$ md5 "' + msg + '"');
    consoleLine(con, '', '');

    try {
        var res = await fetch('/api/md5', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: msg})
        });
        var data = await res.json();

        if (!data.success) {
            consoleLine(con, 'c-warn', 'ERROR: ' + data.error);
            status.className = 'status err';
            status.textContent = data.error;
            return;
        }

        printSteps(con, data.steps);
        consoleLine(con, '', '');
        consoleLine(con, 'c-res', 'MD5 = ' + data.digest);
        consoleLine(con, '', '');

        title.textContent = 'md5 output  [' + data.digest.substring(0, 16) + '...]';
        status.className = 'status';
        status.textContent = 'done — ' + data.digest.length / 2 + ' bytes output';
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
