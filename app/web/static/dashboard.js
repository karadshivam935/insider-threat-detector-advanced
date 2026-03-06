/* global Chart */

const $ = (id) => document.getElementById(id);

const statusPill = $("statusPill");
const refreshBtn = $("refreshBtn");
const errorBox = $("errorBox");

const kpiAlerts24h = $("kpiAlerts24h");
const kpiBlocks = $("kpiBlocks");
const kpiHigh = $("kpiHigh");
const kpiTopTalker = $("kpiTopTalker");
const kpiTopTalkerBytes = $("kpiTopTalkerBytes");

const alertsTbody = $("alertsTbody");
const filterIp = $("filterIp");
const minScore = $("minScore");

const fmtTime = (ts) => new Date(ts * 1000).toLocaleString();
const fmtBytes = (n) => {
  n = Number(n || 0);
  const units = ["B","KB","MB","GB"];
  let u = 0;
  while (n >= 1024 && u < units.length-1) { n/=1024; u++; }
  return `${n.toFixed(u===0?0:1)} ${units[u]}`;
};

function showErr(msg) {
  errorBox.classList.remove("hidden");
  errorBox.textContent = msg;
  statusPill.textContent = "● Error";
  statusPill.className = "text-xs px-3 py-1 rounded-full bg-red-500/15 text-red-300 border border-red-500/30";
}

function clearErr() {
  errorBox.classList.add("hidden");
  errorBox.textContent = "";
  statusPill.textContent = "● Connected";
  statusPill.className = "text-xs px-3 py-1 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30";
}

async function fetchJson(url) {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}`);
  return await r.json();
}

// Charts
let alertsChart, talkersChart;
function initCharts() {
  alertsChart = new Chart($("alertsChart"), {
    type: "line",
    data: { labels: [], datasets: [{ label:"Alerts/min", data:[], tension:0.35 }] },
    options: { responsive:true, maintainAspectRatio:false }
  });

  talkersChart = new Chart($("talkersChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ label:"Bytes (1h)", data:[] }] },
    options: { responsive:true, maintainAspectRatio:false }
  });
}

let lastEvents = [];

function renderTable() {
  const ipq = (filterIp.value || "").trim().toLowerCase();
  const minS = Number(minScore.value || 35);
  alertsTbody.innerHTML = "";

  const rows = (lastEvents || [])
    .filter(e => Number(e.score || 0) >= minS)
    .filter(e => !ipq || String(e.src_ip || "").toLowerCase().includes(ipq))
    .slice(0, 50);

  for (const e of rows) {
    const tr = document.createElement("tr");
    tr.className = "hover:bg-white/5";

    tr.innerHTML = `
      <td class="px-4 py-3 text-slate-300 whitespace-nowrap">${fmtTime(e.ts)}</td>
      <td class="px-4 py-3 font-medium text-slate-100 whitespace-nowrap">${e.src_ip || "-"}</td>
      <td class="px-4 py-3 whitespace-nowrap">${e.score ?? "-"}</td>
      <td class="px-4 py-3 text-slate-300 whitespace-nowrap">${fmtBytes(e.bytes)}</td>
      <td class="px-4 py-3 text-slate-300">${e.reasons || "-"}</td>
    `;
    alertsTbody.appendChild(tr);
  }
}

function updateAlertsChart() {
  const now = Math.floor(Date.now()/1000);
  const start = now - 3600;
  const buckets = new Map();
  for (let t=start; t<=now; t+=60) buckets.set(t-(t%60), 0);

  for (const e of lastEvents || []) {
    const ts = Number(e.ts||0);
    if (ts < start) continue;
    const m = ts - (ts%60);
    buckets.set(m, (buckets.get(m)||0)+1);
  }

  const keys = Array.from(buckets.keys()).sort((a,b)=>a-b);
  alertsChart.data.labels = keys.map(t => new Date(t*1000).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"}));
  alertsChart.data.datasets[0].data = keys.map(k => buckets.get(k));
  alertsChart.update();
}

function updateTalkersChart(topTalkers) {
  const labels = (topTalkers||[]).map(x => x.src_ip);
  const data = (topTalkers||[]).map(x => Number(x.total_bytes||0));
  talkersChart.data.labels = labels;
  talkersChart.data.datasets[0].data = data;
  talkersChart.update();

  if ((topTalkers||[]).length) {
    kpiTopTalker.textContent = topTalkers[0].src_ip;
    kpiTopTalkerBytes.textContent = fmtBytes(topTalkers[0].total_bytes) + " in last 1h";
  } else {
    kpiTopTalker.textContent = "—";
    kpiTopTalkerBytes.textContent = "—";
  }
}

async function refreshAll() {
  try {
    const summary = await fetchJson("/api/summary");
    clearErr();

    kpiAlerts24h.textContent = summary.alerts_24h ?? "—";
    kpiBlocks.textContent = summary.active_blocks ?? "—";
    kpiHigh.textContent = summary.high_24h ?? "—";

    updateTalkersChart(summary.top_talkers_1h || []);

    lastEvents = await fetchJson("/api/events?limit=200");
    renderTable();
    updateAlertsChart();

  } catch (e) {
    showErr(String(e));
  }
}

filterIp.addEventListener("input", renderTable);
minScore.addEventListener("change", renderTable);
refreshBtn.addEventListener("click", refreshAll);

initCharts();
refreshAll();
setInterval(refreshAll, 4000);


// ---- Socket.IO Live Feed ----
const liveFeed = document.getElementById("liveFeed");
const clearFeedBtn = document.getElementById("clearFeedBtn");

function pushFeed(msg, kind="info") {
  if (!liveFeed) return;
  const row = document.createElement("div");
  row.className = "flex gap-2 items-start";
  const dot = document.createElement("span");
  dot.className = "mt-1 h-2 w-2 rounded-full " + (kind==="err" ? "bg-red-400" : "bg-cyan-400");
  const text = document.createElement("div");
  text.className = "text-slate-200";
  text.textContent = msg;
  row.appendChild(dot);
  row.appendChild(text);
  liveFeed.prepend(row);
}

function connectSocket() {
  if (typeof io === "undefined") {
    pushFeed("[SOCKET] socket.io client not loaded", "err");
    return;
  }
  const socket = io();

  socket.on("connect", () => {
    pushFeed("[SOCKET] connected");
  });

  socket.on("disconnect", () => {
    pushFeed("[SOCKET] disconnected", "err");
  });

  // Your backend should emit 'event' messages
  socket.on("event", (msg) => {
    pushFeed("[EVENT] " + JSON.stringify(msg));
    // Refresh UI immediately when event arrives
    try { refreshAll(); } catch(e) {}
  });

  // Optional: blocks channel
  socket.on("block", (msg) => {
    pushFeed("[BLOCK] " + JSON.stringify(msg), "err");
    try { refreshAll(); } catch(e) {}
  });
}

if (clearFeedBtn) clearFeedBtn.addEventListener("click", () => { if(liveFeed) liveFeed.innerHTML=""; });
connectSocket();
