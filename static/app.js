let bwHistory = [];
let selectedPacketId = null;
let packetsCache = [];
let csrfToken = "";

let currentPage = 1;
let pageSize = 50;
let totalPackets = 0;
let isUserScrollingPackets = false;

function getCookie(name) {
  const parts = `; ${document.cookie}`.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(";").shift();
  return "";
}

async function apiFetch(url, options = {}) {
  const opts = { ...options };
  opts.headers = { ...(options.headers || {}) };
  if (opts.method && ["POST", "PUT", "DELETE", "PATCH"].includes(opts.method.toUpperCase())) {
    opts.headers["X-CSRF-Token"] = csrfToken || getCookie("ynetmon_csrf");
  }
  const res = await fetch(url, opts);
  if (res.status === 401) {
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }
  return res;
}

function formatBytes(bytes) {
  const b = Number(bytes) || 0;
  if (b < 1024) return `${b.toFixed(0)} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(2)} MB`;
  return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatRate(bps) {
  return `${formatBytes(bps)}/s`;
}

function formatTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("tr-TR", { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Tabs navigation
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    const target = document.getElementById(btn.dataset.tab);
    if (target) target.classList.add("active");

    if (btn.dataset.tab === "tab-connections") loadConnections();
    if (btn.dataset.tab === "tab-devices") loadDevices();
    if (btn.dataset.tab === "tab-docker") loadDocker();
    if (btn.dataset.tab === "tab-alerts") {
      loadSettings();
      loadAlerts();
    }
  });
});

function updateStorageBadge(st) {
  if (!st) return;
  const el = document.getElementById("storageBadge");
  if (el) {
    el.textContent = `DB: ${st.db_size_mb ?? 0} MB (${st.packets_count ?? 0} pkt)`;
  }
}

async function initStatus() {
  const authRes = await fetch("/api/auth/status");
  const authData = await authRes.json();
  if (!authData.authenticated) {
    window.location.href = "/login";
    return;
  }
  csrfToken = authData.csrf_token || getCookie("ynetmon_csrf");
  document.getElementById("userBadge").textContent = `👤 ${authData.username}`;

  const res = await apiFetch("/api/status");
  const data = await res.json();

  document.getElementById("metricLocalIp").textContent = `Yerel IP: ${data.local_ip}`;
  updateCaptureBadge(data.raw_capture_active);
  updateStorageBadge(data.storage);

  const sel = document.getElementById("ifaceSelect");
  sel.innerHTML = `<option value="all">Tüm Arayüzler (all)</option>`;
  (data.interfaces || []).forEach((ifc) => {
    const opt = document.createElement("option");
    opt.value = ifc.name;
    opt.textContent = `${ifc.name} (${ifc.ip || "IP yok"})`;
    if (ifc.name === data.selected_iface) opt.selected = true;
    sel.appendChild(opt);
  });

  bwHistory = (data.bandwidth_history || []).slice(-60);
  drawBandwidthChart();
}

document.getElementById("btnLogout").addEventListener("click", async () => {
  await apiFetch("/api/auth/logout", { method: "POST" });
  window.location.href = "/login";
});

function updateCaptureBadge(active) {
  const badge = document.getElementById("captureBadge");
  if (!badge) return;
  if (active) {
    badge.className = "badge badge-ok";
    badge.textContent = "L2-L7 DERİN PAKET ANALİZİ";
  } else {
    badge.className = "badge badge-ok";
    badge.textContent = "CANLI SOKET & AKIŞ ANALİZİ";
  }
}

document.getElementById("ifaceSelect").addEventListener("change", async (e) => {
  const res = await apiFetch("/api/interface", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ iface: e.target.value }),
  });
  const data = await res.json();
  updateCaptureBadge(data.raw_capture_active);
});

document.getElementById("btnLabTraffic").addEventListener("click", async () => {
  await apiFetch("/api/lab/generate", { method: "POST" });
  currentPage = 1;
  await loadPackets();
});

document.getElementById("btnClearPackets").addEventListener("click", async () => {
  const res = await apiFetch("/api/packets/clear", { method: "POST" });
  const data = await res.json();
  updateStorageBadge(data.storage);
  currentPage = 1;
  selectedPacketId = null;
  await loadPackets();
});

// Scroll lock detection on packet list pane so scrollbar never jumps while inspecting
const packetListPane = document.getElementById("packetListPane");
packetListPane.addEventListener("scroll", () => {
  isUserScrollingPackets = packetListPane.scrollTop > 35;
  const lbl = document.getElementById("liveStreamLabel");
  if (lbl) {
    lbl.textContent = isUserScrollingPackets ? "Canlı Akış (Kaydırma Kilidi)" : "Canlı Akış";
  }
});

document.getElementById("pageSizeSelect").addEventListener("change", (e) => {
  pageSize = Number(e.target.value) || 50;
  currentPage = 1;
  loadPackets();
});

document.getElementById("btnPrevPage").addEventListener("click", () => {
  if (currentPage > 1) {
    currentPage--;
    loadPackets();
  }
});

document.getElementById("btnNextPage").addEventListener("click", () => {
  const totalPages = Math.max(1, Math.ceil(totalPackets / pageSize));
  if (currentPage < totalPages) {
    currentPage++;
    loadPackets();
  }
});

function hasActivePacketFilters() {
  return Boolean(
    document.getElementById("filterIp").value.trim() ||
    document.getElementById("filterPort").value.trim() ||
    document.getElementById("filterProto").value.trim() ||
    document.getElementById("filterContainer").value.trim() ||
    document.getElementById("filterSearch").value.trim()
  );
}

async function loadPackets() {
  const offset = (currentPage - 1) * pageSize;
  const params = new URLSearchParams({
    limit: String(pageSize),
    offset: String(offset),
  });
  const ip = document.getElementById("filterIp").value.trim();
  const port = document.getElementById("filterPort").value.trim();
  const proto = document.getElementById("filterProto").value.trim();
  const container = document.getElementById("filterContainer").value.trim();
  const search = document.getElementById("filterSearch").value.trim();

  if (ip) params.set("ip", ip);
  if (port) params.set("port", port);
  if (proto) params.set("protocol", proto);
  if (container) params.set("container", container);
  if (search) params.set("search", search);

  const res = await apiFetch(`/api/packets?${params.toString()}`);
  const data = await res.json();
  packetsCache = data.packets || [];
  totalPackets = data.total ?? packetsCache.length;

  const totalPages = Math.max(1, Math.ceil(totalPackets / pageSize));
  if (currentPage > totalPages) currentPage = totalPages;

  document.getElementById("packetCountInfo").textContent =
    `Toplam ${totalPackets} paket (Sayfa başına ${pageSize} gösteriliyor)`;
  document.getElementById("pageIndicator").textContent = `Sayfa ${currentPage} / ${totalPages}`;
  document.getElementById("btnPrevPage").disabled = currentPage <= 1;
  document.getElementById("btnNextPage").disabled = currentPage >= totalPages;

  renderPacketTable(packetsCache);
}

function renderPacketTable(packets) {
  const prevScroll = packetListPane.scrollTop;
  const tbody = document.getElementById("packetTableBody");
  tbody.innerHTML = packets
    .map((p) => {
      const proto = p.l7_proto || p.protocol || "TCP";
      const isSelected = p.id === selectedPacketId ? "selected" : "";
      const src = p.src_port ? `${p.src_ip}:${p.src_port}` : p.src_ip;
      const dst = p.dst_port ? `${p.dst_ip}:${p.dst_port}` : p.dst_ip;
      return `
        <tr class="${isSelected}" data-id="${p.id}">
          <td>${p.id}</td>
          <td>${formatTime(p.timestamp)}</td>
          <td>${escapeHtml(src)}</td>
          <td>${escapeHtml(dst)}</td>
          <td><span class="proto-pill proto-${escapeHtml(proto)}">${escapeHtml(proto)}</span></td>
          <td>${p.length} B</td>
          <td>${escapeHtml(p.container_name || p.process_name || "-")}</td>
          <td>${escapeHtml(p.info || p.domain_sni || "")}</td>
        </tr>
      `;
    })
    .join("");

  packetListPane.scrollTop = prevScroll;

  tbody.querySelectorAll("tr").forEach((row) => {
    row.addEventListener("click", () => {
      const id = Number(row.dataset.id);
      selectedPacketId = id;
      tbody.querySelectorAll("tr").forEach((r) => r.classList.remove("selected"));
      row.classList.add("selected");
      showPacketDetail(id);
    });
  });

  if (!selectedPacketId && packets.length > 0) {
    selectedPacketId = packets[0].id;
    showPacketDetail(selectedPacketId);
  }
}

async function showPacketDetail(pktId) {
  let pkt = packetsCache.find((p) => p.id === pktId);
  if (!pkt) {
    const res = await apiFetch(`/api/packets/${pktId}`);
    if (!res.ok) return;
    pkt = await res.json();
  }
  const osi = pkt.osi || {};
  const l1 = osi.layer1 || {};
  const l2 = osi.layer2 || {};
  const l3 = osi.layer3 || {};
  const l4 = osi.layer4 || {};
  const l5 = osi.layer5 || {};
  const l6 = osi.layer6 || {};
  const l7 = osi.layer7 || {};
  const dec = osi.decision || {};

  const flagHtml = (l4.flag_details || [])
    .map(
      (f) => `<div class="flag-item"><strong>[${escapeHtml(f.flag)}] ${escapeHtml(f.name)}:</strong> ${escapeHtml(f.desc)}</div>`
    )
    .join("");

  const decBadgeClass = dec.is_benign === false ? "badge-warn" : "badge-ok";
  const decHtml = dec.direction
    ? `
    <div class="osi-layer" style="border-left-color:${dec.is_benign === false ? "#ef4444" : "#22c55e"};">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:6px;">
        <h4 style="margin:0;">🛡️ Karar Motoru &amp; Tehdit Analizi</h4>
        <span class="badge ${decBadgeClass}">Risk: ${dec.risk_score ?? 0}/100 (${escapeHtml(dec.direction)})</span>
      </div>
      <div class="osi-kv">
        <span>Sağlayıcı / Ağ: <strong>${escapeHtml(dec.provider || "-")}</strong></span>
        <span>Durum: <strong>${dec.is_benign === false ? "İncelenmeli (Dış İstek)" : "Güvenli / Normal Trafik"}</strong></span>
      </div>
      <div class="osi-learn">🔍 ${escapeHtml(dec.reason || "")}</div>
    </div>
    `
    : "";

  const pane = document.getElementById("packetDetailPane");
  pane.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:6px;">
      <h3>Paket #${pkt.id} OSI 7 Katman Analizi</h3>
      <span class="proto-pill proto-${escapeHtml(pkt.l7_proto || pkt.protocol)}">${escapeHtml(pkt.l7_proto || pkt.protocol)} (${pkt.length} Bayt)</span>
    </div>

    ${decHtml}

    <div class="osi-layer l7">
      <h4>${escapeHtml(l7.title || "Katman 7 - Uygulama (Application)")}</h4>
      <div class="osi-kv">
        <span>Servis / Protokol: <strong>${escapeHtml(l7.l7_proto || pkt.l7_proto || pkt.protocol)}</strong></span>
        ${l7.domain_sni ? `<span>Domain / SNI: <strong>${escapeHtml(l7.domain_sni)}</strong></span>` : ""}
        ${pkt.process_name ? `<span>Uygulama / Süreç: <strong>${escapeHtml(pkt.process_name)}</strong></span>` : ""}
        <span>Özet: <strong>${escapeHtml(l7.info || pkt.info)}</strong></span>
      </div>
      <div class="osi-learn">💡 ${escapeHtml(l7.learn || "")}</div>
    </div>

    <div class="osi-layer l6">
      <h4>${escapeHtml(l6.title || "Katman 6 - Sunum (Presentation)")}</h4>
      <div class="osi-kv">
        <span>Şifreleme: <strong>${escapeHtml(l6.encryption || "-")}</strong></span>
        <span>Kodlama: <strong>${escapeHtml(l6.encoding || "-")}</strong></span>
        <span>MIME / İçerik: <strong>${escapeHtml(l6.mime_type || "-")}</strong></span>
        <span>Sıkıştırma: <strong>${escapeHtml(l6.compression || "-")}</strong></span>
      </div>
      <div class="osi-learn">💡 ${escapeHtml(l6.learn || "")}</div>
    </div>

    <div class="osi-layer l5">
      <h4>${escapeHtml(l5.title || "Katman 5 - Oturum (Session)")}</h4>
      <div class="osi-kv">
        <span>Oturum Kimliği: <strong>${escapeHtml(l5.session_id || `${pkt.src_ip}:${pkt.src_port} ↔ ${pkt.dst_ip}:${pkt.dst_port}`)}</strong></span>
        <span>Oturum Durumu: <strong>${escapeHtml(l5.session_phase || "-")}</strong></span>
        <span>İletişim Türü: <strong>${escapeHtml(l5.dialogue_mode || "Full-Duplex")}</strong></span>
        <span>İlişkili Süreç: <strong>${escapeHtml(l5.process || pkt.process_name || pkt.container_name || "kernel")}</strong></span>
      </div>
      <div class="osi-learn">💡 ${escapeHtml(l5.learn || "")}</div>
    </div>

    <div class="osi-layer l4">
      <h4>${escapeHtml(l4.title || "Katman 4 - Taşıma (Transport)")}</h4>
      <div class="osi-kv">
        <span>Kaynak Port: <strong>${l4.src_port ?? pkt.src_port}</strong></span>
        <span>Hedef Port: <strong>${l4.dst_port ?? pkt.dst_port}</strong></span>
        ${pkt.tcp_flags ? `<span>Bayraklar: <strong>${escapeHtml(pkt.tcp_flags)}</strong></span>` : ""}
        ${pkt.protocol === "TCP" ? `<span>Seq: <strong>${l4.seq_num}</strong> | Ack: <strong>${l4.ack_num}</strong> | Win: <strong>${l4.window_size}</strong></span>` : ""}
      </div>
      <div class="osi-learn">💡 ${escapeHtml(l4.learn || "")}</div>
      ${flagHtml ? `<div class="flag-box">${flagHtml}</div>` : ""}
    </div>

    <div class="osi-layer l3">
      <h4>${escapeHtml(l3.title || "Katman 3 - Ağ (Network / IP)")}</h4>
      <div class="osi-kv">
        <span>Kaynak IP: <strong>${escapeHtml(l3.src_ip || pkt.src_ip)}</strong></span>
        <span>Hedef IP: <strong>${escapeHtml(l3.dst_ip || pkt.dst_ip)}</strong></span>
        <span>IP Sürümü: <strong>${escapeHtml(l3.ip_version || "IPv4")}</strong></span>
        <span>TTL: <strong>${l3.ttl ?? pkt.ttl}</strong></span>
        <span>OS Tahmini: <strong>${escapeHtml(l3.os_hint || "-")}</strong></span>
      </div>
      <div class="osi-learn">💡 ${escapeHtml(l3.learn || "")}</div>
    </div>

    <div class="osi-layer l2">
      <h4>${escapeHtml(l2.title || "Katman 2 - Veri Bağı (Data Link / Ethernet)")}</h4>
      <div class="osi-kv">
        <span>Kaynak MAC: <strong>${escapeHtml(l2.src_mac || pkt.src_mac)}</strong></span>
        <span>Hedef MAC: <strong>${escapeHtml(l2.dst_mac || pkt.dst_mac)}</strong></span>
        <span>EtherType: <strong>${escapeHtml(l2.eth_type || pkt.eth_type)}</strong></span>
        ${l2.frame_size ? `<span>Çerçeve Boyutu: <strong>${escapeHtml(l2.frame_size)}</strong></span>` : ""}
      </div>
      <div class="osi-learn">💡 ${escapeHtml(l2.learn || "")}</div>
    </div>

    <div class="osi-layer l1">
      <h4>${escapeHtml(l1.title || "Katman 1 - Fiziksel (Physical)")}</h4>
      <div class="osi-kv">
        <span>Ağ Arabirimi: <strong>${escapeHtml(l1.iface || pkt.iface || "eth0")}</strong></span>
        <span>MTU: <strong>${escapeHtml(String(l1.mtu || 1500))} Bayt</strong></span>
        <span>Hat Hızı: <strong>${escapeHtml(l1.speed || "1000 Mbps")}</strong></span>
        <span>Fiziksel Ortam: <strong>${escapeHtml(l1.medium || "Ethernet")}</strong></span>
        <span>Durum: <strong>${escapeHtml(l1.status || "Aktif (Link UP)")}</strong></span>
      </div>
      <div class="osi-learn">💡 ${escapeHtml(l1.learn || "")}</div>
    </div>

    <h4 style="margin:12px 0 6px;font-size:13px;">Paket Payload (Hex &amp; ASCII İnceleyici)</h4>
    <div class="hex-viewer">${escapeHtml(pkt.payload_hex || "Payload verisi yok (Sadece başlık paketi).")}</div>
  `;
}

document.getElementById("btnApplyFilter").addEventListener("click", () => {
  currentPage = 1;
  loadPackets();
});
document.getElementById("btnClearFilter").addEventListener("click", () => {
  document.getElementById("filterIp").value = "";
  document.getElementById("filterPort").value = "";
  document.getElementById("filterProto").value = "";
  document.getElementById("filterContainer").value = "";
  document.getElementById("filterSearch").value = "";
  currentPage = 1;
  loadPackets();
});

// Bandwidth Chart
function drawBandwidthChart() {
  const canvas = document.getElementById("bwChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  if (bwHistory.length < 2) return;
  const maxVal = Math.max(
    1024,
    ...bwHistory.map((p) => Math.max(p.rx_bps || 0, p.tx_bps || 0))
  );

  const drawLine = (key, color) => {
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    bwHistory.forEach((pt, idx) => {
      const x = (idx / Math.max(1, bwHistory.length - 1)) * (w - 10) + 5;
      const y = h - 6 - ((pt[key] || 0) / maxVal) * (h - 14);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  };

  drawLine("rx_bps", "#22c55e");
  drawLine("tx_bps", "#a855f7");
}

// Active Connections Tab
async function loadConnections() {
  const res = await apiFetch("/api/connections");
  const data = await res.json();
  const tbody = document.getElementById("connTableBody");
  tbody.innerHTML = (data.connections || [])
    .map(
      (c) => `
      <tr>
        <td><span class="proto-pill proto-${escapeHtml(c.proto)}">${escapeHtml(c.proto)}</span></td>
        <td>${escapeHtml(c.local_ip)}:${c.local_port}</td>
        <td>${c.remote_ip ? `${escapeHtml(c.remote_ip)}:${c.remote_port}` : "-"}</td>
        <td><span class="badge badge-ok">${escapeHtml(c.remote_provider || "-")}</span></td>
        <td><strong>${escapeHtml(c.status)}</strong></td>
        <td style="white-space:normal;max-width:380px;color:#cbd5e1;">${escapeHtml(c.status_explain)}</td>
        <td>${escapeHtml(c.process)} (${c.pid})</td>
        <td>${escapeHtml(c.container || "-")}</td>
      </tr>
    `
    )
    .join("");
}
document.getElementById("btnRefreshConns").addEventListener("click", loadConnections);

// Devices Tab (CSP-safe event listeners)
async function loadDevices() {
  const q = document.getElementById("deviceSearch").value.trim();
  const res = await apiFetch(`/api/devices${q ? `?search=${encodeURIComponent(q)}` : ""}`);
  const data = await res.json();
  const tbody = document.getElementById("deviceTableBody");
  tbody.innerHTML = (data.devices || [])
    .map(
      (d) => `
      <tr>
        <td><strong>${escapeHtml(d.ip)}</strong></td>
        <td>${escapeHtml(d.mac || "-")}</td>
        <td>${escapeHtml(d.container_name || "-")}</td>
        <td class="tx-color">${formatBytes(d.bytes_sent)}</td>
        <td class="rx-color">${formatBytes(d.bytes_recv)}</td>
        <td><strong>${formatBytes(d.total_bytes)}</strong></td>
        <td>${d.packets_sent} / ${d.packets_recv}</td>
        <td>${escapeHtml(d.protocols)}</td>
        <td>${formatTime(d.last_seen)}</td>
        <td><button class="btn btn-outline btn-sm btn-filter-ip" data-ip="${escapeHtml(d.ip)}">Paketleri Gör</button></td>
      </tr>
    `
    )
    .join("");

  tbody.querySelectorAll(".btn-filter-ip").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.getElementById("filterIp").value = btn.dataset.ip;
      currentPage = 1;
      document.querySelector('[data-tab="tab-packets"]').click();
      loadPackets();
    });
  });
}
document.getElementById("btnSearchDevices").addEventListener("click", loadDevices);

// Docker Tab (CSP-safe event listeners)
async function loadDocker(refresh = false) {
  const res = await apiFetch(`/api/docker?refresh=${refresh}`);
  const data = await res.json();
  const grid = document.getElementById("dockerGrid");
  const list = data.containers || [];
  if (list.length === 0) {
    grid.innerHTML = `<div class="settings-card"><p class="muted">Şu an çalışan bir Docker container bulunamadı veya Docker servisi kapalı. YNetMon container'ları otomatik algılar.</p></div>`;
    return;
  }
  grid.innerHTML = list
    .map(
      (c) => `
      <div class="docker-card">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <h4>🐳 ${escapeHtml(c.name)}</h4>
          <span class="badge badge-ok">${escapeHtml(c.network_mode)}</span>
        </div>
        <div class="muted">İmaj: <strong>${escapeHtml(c.image)}</strong> (${escapeHtml(c.id)})</div>
        <div class="muted">Durum: ${escapeHtml(c.status)}</div>
        <div class="muted">IP Adresleri: <strong>${escapeHtml((c.ips || []).join(", ") || "host/none")}</strong></div>
        <div class="muted">Portlar: <code>${escapeHtml(c.ports || "-")}</code></div>
        <div class="osi-learn">${escapeHtml(c.stats)}</div>
        <button class="btn btn-outline btn-filter-container" data-container="${escapeHtml(c.name)}">Bu Container'ın Paketlerini İncele</button>
      </div>
    `
    )
    .join("");

  grid.querySelectorAll(".btn-filter-container").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.getElementById("filterContainer").value = btn.dataset.container;
      currentPage = 1;
      document.querySelector('[data-tab="tab-packets"]').click();
      loadPackets();
    });
  });
}
document.getElementById("btnRefreshDocker").addEventListener("click", () => loadDocker(true));

// Alerts, Storage & Settings Tab
async function loadSettings() {
  const res = await apiFetch("/api/settings");
  const s = await res.json();
  document.getElementById("setHubUrl").value = s.hub_url || "";
  document.getElementById("setHubApiKey").value = s.hub_api_key || "";
  document.getElementById("setMaxPackets").value = s.max_stored_packets || "5000";
  document.getElementById("setRetentionHours").value = s.retention_hours || "24";
  document.getElementById("setFlowDedup").value = s.flow_dedup_seconds || "30";
  document.getElementById("setAllowlistIps").value = s.allowlist_ips || "";
  document.getElementById("setWebhookUrl").value = s.webhook_url || "";
  document.getElementById("setTgToken").value = s.telegram_bot_token || "";
  document.getElementById("setTgChat").value = s.telegram_chat_id || "";
  document.getElementById("setSignalMode").value = s.signal_mode || "callmebot";
  document.getElementById("setSignalPhone").value = s.signal_phone || "";
  document.getElementById("setSignalTarget").value = s.signal_target || "";
  document.getElementById("setSignalApiUrl").value = s.signal_api_url || "";
  document.getElementById("setWatchedPorts").value = s.watched_ports || "21,22,23,3389,4444,5900";
  document.getElementById("setBwThreshold").value = s.bandwidth_threshold_mbps || "50.0";
  document.getElementById("setScanThreshold").value = s.port_scan_threshold || "15";
}

document.getElementById("btnVacuumDb").addEventListener("click", async () => {
  const statusEl = document.getElementById("settingsStatus");
  statusEl.style.color = "#38bdf8";
  statusEl.textContent = "Veritabanı optimize ediliyor...";
  const res = await apiFetch("/api/storage/vacuum", { method: "POST" });
  const data = await res.json();
  updateStorageBadge(data.storage);
  statusEl.style.color = "#22c55e";
  statusEl.textContent = `✓ Optimize edildi: ${data.storage.db_size_mb} MB (${data.storage.packets_count} paket).`;
});

document.getElementById("btnDetectTgChat").addEventListener("click", async () => {
  const statusEl = document.getElementById("settingsStatus");
  statusEl.style.color = "#38bdf8";
  statusEl.textContent = "Telegram'dan son mesajınız aranıyor...";
  const bot_token = document.getElementById("setTgToken").value.trim();
  const res = await apiFetch("/api/telegram/detect-chat-id", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bot_token }),
  });
  const data = await res.json();
  if (data.ok && data.chat_id) {
    document.getElementById("setTgChat").value = data.chat_id;
    statusEl.style.color = "#22c55e";
  } else {
    statusEl.style.color = "#f59e0b";
  }
  statusEl.textContent = data.detail;
});

document.getElementById("settingsForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const statusEl = document.getElementById("settingsStatus");
  const payload = {
    hub_url: document.getElementById("setHubUrl").value.trim(),
    hub_api_key: document.getElementById("setHubApiKey").value.trim(),
    max_stored_packets: document.getElementById("setMaxPackets").value.trim(),
    retention_hours: document.getElementById("setRetentionHours").value.trim(),
    flow_dedup_seconds: document.getElementById("setFlowDedup").value.trim(),
    allowlist_ips: document.getElementById("setAllowlistIps").value.trim(),
    webhook_url: document.getElementById("setWebhookUrl").value.trim(),
    telegram_bot_token: document.getElementById("setTgToken").value.trim(),
    telegram_chat_id: document.getElementById("setTgChat").value.trim(),
    signal_mode: document.getElementById("setSignalMode").value,
    signal_phone: document.getElementById("setSignalPhone").value.trim(),
    signal_target: document.getElementById("setSignalTarget").value.trim(),
    signal_api_url: document.getElementById("setSignalApiUrl").value.trim(),
    watched_ports: document.getElementById("setWatchedPorts").value.trim(),
    bandwidth_threshold_mbps: document.getElementById("setBwThreshold").value.trim(),
    port_scan_threshold: document.getElementById("setScanThreshold").value.trim(),
  };
  const res = await apiFetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) {
    statusEl.style.color = "#ef4444";
    statusEl.textContent = data.detail || "Ayarlar kaydedilemedi.";
    return;
  }
  const stRes = await apiFetch("/api/storage");
  updateStorageBadge(await stRes.json());
  statusEl.style.color = "#22c55e";
  statusEl.textContent = "✓ Ayarlar kaydedildi ve saklama sınırları uygulandı.";
});

document.getElementById("passwordForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const statusEl = document.getElementById("passwordStatus");
  const current_password = document.getElementById("curPassword").value;
  const new_password = document.getElementById("newPassword").value;
  const res = await apiFetch("/api/auth/change-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current_password, new_password }),
  });
  const data = await res.json();
  if (!res.ok) {
    statusEl.style.color = "#ef4444";
    statusEl.textContent = data.detail || "Şifre güncellenemedi.";
    return;
  }
  csrfToken = data.csrf_token || getCookie("ynetmon_csrf");
  document.getElementById("curPassword").value = "";
  document.getElementById("newPassword").value = "";
  statusEl.style.color = "#22c55e";
  statusEl.textContent = "✓ Şifre güncellendi ve diğer açık oturumlar sonlandırıldı.";
});

document.getElementById("btnTestWebhook").addEventListener("click", async () => {
  const statusEl = document.getElementById("settingsStatus");
  statusEl.textContent = "Test bildirimi gönderiliyor...";
  const res = await apiFetch("/api/alerts/test", { method: "POST" });
  const data = await res.json();
  statusEl.textContent = data.detail;
  loadAlerts();
});

async function loadAlerts() {
  const res = await apiFetch("/api/alerts");
  const data = await res.json();
  const tbody = document.getElementById("alertsTableBody");
  tbody.innerHTML = (data.alerts || [])
    .map(
      (a) => `
      <tr>
        <td>${formatTime(a.timestamp)}</td>
        <td><span class="proto-pill ${a.severity === "high" ? "proto-ICMP" : "proto-HTTP"}">${escapeHtml(a.severity.toUpperCase())}</span></td>
        <td><strong>${escapeHtml(a.rule_name)}</strong></td>
        <td>${escapeHtml(a.src_ip)} -&gt; ${escapeHtml(a.dst_ip)}:${a.dst_port}</td>
        <td style="white-space:normal;">${escapeHtml(a.message)}</td>
      </tr>
    `
    )
    .join("");
}
document.getElementById("btnRefreshAlerts").addEventListener("click", loadAlerts);
document.getElementById("btnClearAlerts").addEventListener("click", async () => {
  await apiFetch("/api/alerts/clear", { method: "POST" });
  loadAlerts();
});

// Live WebSocket connection
function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/ws/live`);

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    const bw = msg.bandwidth || {};
    document.getElementById("metricRx").textContent = formatRate(bw.rx_bps || 0);
    document.getElementById("metricTx").textContent = formatRate(bw.tx_bps || 0);
    document.getElementById("metricRxPps").textContent = `${bw.rx_pps || 0} pkt/s`;
    document.getElementById("metricTxPps").textContent = `${bw.tx_pps || 0} pkt/s`;
    document.getElementById("metricConns").textContent = msg.active_connections_count ?? 0;
    document.getElementById("metricDocker").textContent = msg.docker_count ?? 0;

    updateCaptureBadge(msg.raw_capture_active);

    bwHistory.push(bw);
    if (bwHistory.length > 60) bwHistory.shift();
    drawBandwidthChart();

    // Only auto-refresh DOM table if on Page 1, Live Stream checked, no active filters, and user is NOT scrolling down
    if (
      currentPage === 1 &&
      !isUserScrollingPackets &&
      document.getElementById("chkLiveStream").checked &&
      !hasActivePacketFilters() &&
      Array.isArray(msg.recent_packets) &&
      msg.recent_packets.length > 0
    ) {
      const latestId = msg.recent_packets[0].id;
      if (!packetsCache.length || packetsCache[0].id !== latestId) {
        loadPackets();
      }
    }
  };

  ws.onclose = (ev) => {
    if (ev.code === 1008) {
      window.location.href = "/login";
      return;
    }
    setTimeout(connectWebSocket, 2500);
  };
}

(async () => {
  await initStatus();
  await loadPackets();
  connectWebSocket();
})();
