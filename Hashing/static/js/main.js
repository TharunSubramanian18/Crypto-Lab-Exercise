// Shared terminal console helpers

function span(cls, text) {
    const s = document.createElement('span');
    s.className = cls;
    s.textContent = text;
    return s;
}

function consoleLine(el, cls, text) {
    const div = document.createElement('div');
    if (cls) {
        div.appendChild(span(cls, text));
    } else {
        div.textContent = text;
    }
    el.appendChild(div);
}

function consoleClear(el) { el.innerHTML = ''; }

function consoleScroll(el) { el.scrollTop = el.scrollHeight; }

function copyConsole() {
    const el = document.getElementById('console');
    navigator.clipboard.writeText(el.innerText || el.textContent);
}

function sep(el, char) {
    char = char || '-';
    consoleLine(el, 'c-sep', char.repeat(80));
}
