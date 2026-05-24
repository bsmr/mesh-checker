(() => {
  const root = document.getElementById("status");
  const PROTOS = ["icmp", "tcp", "udp", "https"];
  const es = new EventSource("/ui/sse/status");

  es.addEventListener("status", (ev) => {
    let data;
    try { data = JSON.parse(ev.data); }
    catch (e) { setMessage(root, "parse error"); return; }
    replaceWith(root, renderTable(data));
  });
  es.onerror = () => { setMessage(root, "stream lost; reconnecting…"); };

  function setMessage(parent, msg) {
    const p = document.createElement("p");
    p.textContent = msg;
    replaceWith(parent, p);
  }

  function replaceWith(parent, node) {
    parent.replaceChildren(node);
  }

  function renderTable(data) {
    const observers = Object.keys(data.observers || {}).sort();
    if (observers.length === 0) {
      const p = document.createElement("p");
      p.textContent = "no data yet";
      return p;
    }
    const peers = new Set();
    observers.forEach(o => Object.keys((data.observers[o] || {}).samples || {}).forEach(p => peers.add(p)));
    const peerList = Array.from(peers).sort();

    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    ["observer", "peer", ...PROTOS].forEach(h => {
      const th = document.createElement("th");
      th.textContent = h;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    observers.forEach(observer => {
      peerList.forEach(peer => {
        const row = document.createElement("tr");
        appendCell(row, observer);
        appendCell(row, peer);
        const samples = ((data.observers[observer] || {}).samples || {})[peer] || {};
        PROTOS.forEach(proto => {
          const cell = document.createElement("td");
          const state = (samples[proto] && samples[proto].state) || "unknown";
          cell.textContent = state;
          cell.className = state;
          row.appendChild(cell);
        });
        tbody.appendChild(row);
      });
    });
    table.appendChild(tbody);
    return table;
  }

  function appendCell(row, text) {
    const td = document.createElement("td");
    td.textContent = text;
    row.appendChild(td);
  }
})();
