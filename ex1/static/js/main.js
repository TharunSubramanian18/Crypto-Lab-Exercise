function run(encrypt) {
    const algo = document.querySelector("input[name='algo']:checked").value;

    fetch("/process", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            algorithm: algo,
            text: document.getElementById("inp").value,
            key: document.getElementById("key").value,
            encrypt: encrypt
        })
    })
    .then(res => res.json())
    .then(data => {
        document.getElementById("out").value = data.output;
        document.getElementById("steps").textContent = data.steps;
    });
}
