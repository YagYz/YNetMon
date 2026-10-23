# YNetMon — Homelab Network Traffic Monitor & Educational OSI Packet Analyzer

**YNetMon**, Homelab sunucuları için geliştirilmiş, **Python (FastAPI) + SQLite (WAL) + Scapy/psutil + Modern Web Arayüzü** tabanlı gerçek zamanlı ağ trafiği izleme, Docker container ağ haritalama, akıllı tehdit karar motoru ve eğitici OSI katman (L2 / L3 / L4 / L7) paket inceleme aracıdır.

## Öne Çıkan Özellikler

- **Eğitici OSI Katman (L2–L7) Paket İnceleyici (Wireshark Görünümü)**:
  - **Katman 2 (Data Link)**: Kaynak/Hedef MAC adresleri ve EtherType
  - **Katman 3 (Network)**: IPv4/IPv6, TTL üzerinden işletim sistemi tahmini
  - **Katman 4 (Transport)**: TCP/UDP/ICMP, TCP Bayraklarının (`SYN`, `ACK`, `PSH`, `FIN`, `RST`) görevleri, Sequence/Ack numaraları
  - **Katman 7 (Application)**: DNS sorguları, TLS ClientHello **SNI** (HTTPS'te hangi domaine gidildiği), HTTP başlıkları ve **Hex + ASCII Payload** görüntüleyici
- **Akıllı Tehdit & Karar Motoru (`app/intel.py`)**:
  - Giden (`OUTBOUND`), istemci dönüş (`INBOUND_RETURN`) ve dışarıdan gelen (`INBOUND_EXTERNAL`) trafiği birbirinden ayırır.
  - Valve/Steam, Cloudflare, Google, GitHub ve Tailscale ağ bloklarını ve yerel istemci süreçlerini otomatik tanıyarak yanlış (false-positive) port taraması alarmlarını engeller.
- **Docker Container Trafik Haritası**:
  - Çalışan container'ların IP ve port eşlemelerini otomatik algılar, paketleri ilgili container ile etiketler.
- **Otomatik Disk & Saklama Yönetimi**:
  - Tekrarlayan veri akışlarını tekilleştirir (`flow_dedup_seconds`), maksimum paket sayısını ve saklama süresini (`retention_hours`) korur, SQLite `incremental_vacuum` ve `WAL truncate` ile disk kullanımını sabit tutar.
- **Çoklu Bildirim & Merkezi Bot Gateway Entegrasyonu**:
  - **Merkezi Homelab Bot Hub (`POST` Webhook + `GET /api/v1/integration/*` REST API)**
  - **Telegram Bot** (Otomatik Chat ID algılama destekli)
  - **Signal** (CallMeBot & `signal-cli-rest-api`)
  - **Discord / Slack / Genel Webhook**
- **Tam Güvenlik Mimarisi**:
  - PBKDF2-HMAC-SHA256 (600.000 iterasyon) şifreleme, sabit zamanlı (timing-attack korumalı) giriş, Brute-Force kilidi, `HttpOnly`/`SameSite=Strict` oturum çerezleri, CSRF koruması, CSWSH Origin kontrolü, sıkı CSP başlıkları ve SSRF koruması.

## Kurulum ve Çalıştırma

### 1. Docker Compose ile Çalıştırma (Önerilen)

```bash
git clone <REPO_URL>
cd YNetMon
docker compose up -d --build
```

### 2. Yerel Python Ortamında Çalıştırma

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Standart mod (Canlı Soket Akışı + Bant Genişliği + OSI Lab)
uvicorn app.main:app --host 0.0.0.0 --port 8765

# Root yetkisi olmadan L2-L7 ham paket yakalama yetkisi tanımlamak için (Opsiyonel):
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python3)
```

Tarayıcıdan `http://localhost:8765` adresine gidin. İlk açılışta yönetici hesabınızı oluşturmanız istenecektir.

## Dış Servis ve Bot Hub Entegrasyon API'si

Ayarlar sekmesinden bir `Bot Hub API Key` tanımladıktan sonra dış servisler veya merkezi Telegram botunuz `X-API-Key` başlığı ile aşağıdaki uç noktaları sorgulayabilir:

```bash
curl -H "X-API-Key: GIZLI_ANAHTARINIZ" http://localhost:8765/api/v1/integration/summary
curl -H "X-API-Key: GIZLI_ANAHTARINIZ" http://localhost:8765/api/v1/integration/alerts
curl -H "X-API-Key: GIZLI_ANAHTARINIZ" http://localhost:8765/api/v1/integration/docker
```
