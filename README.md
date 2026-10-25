# YNetMon — Homelab Network Guard & 7-Layer OSI Traffic Inspector

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker Support](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org)

**YNetMon**, Homelab sunucuları ve ağ geliştiricileri için tasarlanmış; **Python (FastAPI) + SQLite (WAL) + Scapy/psutil + Vanilla JS Modern Web Arayüzü** tabanlı gerçek zamanlı ağ trafiği izleme, Docker container ağ haritalama, akıllı tehdit filtreleme ve **7 Katmanlı OSI Modeli (L1–L7)** paket analiz aracıdır.

---

## ⚡ Hızlı Kurulum (Tek Komut)

Herhangi bir Debian/Ubuntu veya Linux dağıtımında tek komutla kurulum sihirbazını çalıştırabilirsiniz:

```bash
curl -fsSL https://raw.githubusercontent.com/YagYz/YNetMon/main/install.sh | bash
```

Veya depoyu klonlayarak:

```bash
git clone https://github.com/YagYz/YNetMon.git
cd YNetMon
./install.sh
```

Kurulum tamamlandığında tarayıcınızdan `http://<sunucu-ip>:8765` adresine giderek ilk yönetici hesabınızı belirleyebilirsiniz.

---

## 🔬 Tam 7 Katmanlı OSI Model İnceleyicisi (L1 – L7)

Trafiğin üzerindeki herhangi bir pakete tıklandığında Wireshark benzeri derinlemesine 7 katman analizi sunulur:

| Katman | Tanım | İncelenen Veriler & Görev |
|---|---|---|
| **L7 — Uygulama** | *Application* | HTTP Metot/URI, DNS Sorguları (`A`, `AAAA`), TLS **SNI** (Gidilen Domain), SSH Sürümü |
| **L6 — Sunum** | *Presentation* | Veri Kodlama (ASCII, UTF-8, Binary), TLS 1.2/1.3 Şifreleme Durumu, MIME Tipi, Gzip Sıkıştırma |
| **L5 — Oturum** | *Session* | TCP Oturum Fazı (`SYN_SENT`, `ESTABLISHED`, `TERMINATING`), Full-Duplex / Simplex, Socket Süreci |
| **L4 — Taşıma** | *Transport* | TCP/UDP/ICMP, Portlar, Bayrak Anlatımları (`SYN`, `ACK`, `PSH`, `FIN`, `RST`), Seq / Ack / Win |
| **L3 — Ağ** | *Network* | Kaynak / Hedef IP, IPv4/IPv6, TTL (Time-To-Live) üzerinden Gönderici İşletim Sistemi Tahmini |
| **L2 — Veri Bağı** | *Data Link* | Kaynak ve Hedef Donanımsal MAC Adresleri, EtherType (IPv4: 0x0800, ARP: 0x0806), Çerçeve Boyutu |
| **L1 — Fiziksel** | *Physical* | Ağ Arabirimi (`eth0`, `docker0`, `tailscale0`), MTU Boyutu (1500B / 9000B), Hat Hızı ve Link Durumu |

Ayrıca her paketin alt kısmında renkli ve hizalanmış **Hex Dump & ASCII Payload** inceleyicisi yer alır.

---

## 🛡️ Akıllı Tehdit & Karar Motoru (`app/intel.py`)

Geleneksel IDS/IPS araçlarının aksine YNetMon, homelab trafiğini akıllıca sınıflandırır:
- **Trafik Yönü Analizi**: İstemciden çıkan giden (`OUTBOUND`), sunucudan dönen yanıtlar (`INBOUND_RETURN`) ve doğrudan dışarıdan içeri gelen istekleri (`INBOUND_EXTERNAL`) ayrıştırır.
- **Sağlayıcı CIDR Tanıma**: Valve/Steam (`155.133.x.x`), Cloudflare, Google, GitHub, Tailscale ve Docker subnet'lerini otomatik tanır.
- **Süreç & Port Beyaz Listesi**: Yerel istemci süreçleri (örn. `steam`, `brave`, `curl`) tarafından açılan çoklu soketleri "port taraması" olarak algılamaz (False-Positive engelleme).

---

## 🐳 Docker Container Trafik Haritası

- `/var/run/docker.sock` üzerinden çalışan container'ların IP'lerini ve port yayınlarını otomatik izler.
- Ağ akışındaki paketleri ilgili container adı (`container_name`) ile etiketler.
- Her container için anlık bant genişliği (Rx/Tx Bps) ve açık soket sayısını görüntüler.

---

## 💾 Otomatik Disk & Bellek Optimizasyonu

Homelab sunucularında disk şişmesini önleyen yerleşik korumalar:
- **5.000 Paket Saklama Limiti**: Eski paketler FIFO mantığıyla otomatik rotasyona tabi tutulur.
- **Akış Tekilleştirme (Flow Dedup)**: Aynı IP:Port çifti arasındaki tekrarlayan paketler belirli periyotta tekilleştirilir.
- **SQLite WAL & Otomatik Vakumlama**: `PRAGMA incremental_vacuum` ve `wal_checkpoint(TRUNCATE)` ile disk alanı minimumda tutulur.

---

## 🔔 Çok Kanallı Bildirim & Bot Hub Entegrasyonu

- **Telegram Bot**: Otomatik Chat ID bulucu ile tek tıkla kurulum, HTML biçimli anlık bildirimler.
- **Signal**: CallMeBot ve `signal-cli-rest-api` desteği.
- **Discord / Webhook**: JSON formatında anlık alarm fırlatma.
- **Merkezi YBotHub Gateway**:
  - `GET /api/v1/integration/summary`
  - `GET /api/v1/integration/alerts`
  - `GET /api/v1/integration/docker`

---

## 🚀 Manuel Kurulum Seçenekleri

### 1. Docker Compose ile Kurulum

```yaml
services:
  ynetmon:
    image: ghcr.io/yagyz/ynetmon:latest
    build: .
    container_name: ynetmon-app
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    security_opt:
      - no-new-privileges:true
    volumes:
      - ./data:/app/data
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - YNETMON_PORT=8765
      - YNETMON_DB=/app/data/ynetmon.db
```

```bash
docker compose up -d --build
```

### 2. Yerel Python 3 Ortamında Çalıştırma

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Non-root raw paket yakalama yetkisi (Linux):
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python3)

# Servisi başlat:
python3 -m app.main
```

---

## 🔒 Güvenlik Mimarisi

- **PBKDF2-HMAC-SHA256**: 600.000 tur parola karma işlemi ve zamanlama saldırılarına karşı sabit zamanlı karşılaştırma.
- **Brute-Force Koruması**: 5 hatalı denemede 15 dakika IP bazlı kilitleme.
- **Gelişmiş Web Güvenliği**: CSRF çerezi ve başlığı, CSWSH (Origin/Referer kontrolü), `HttpOnly` / `SameSite=Strict` oturum çerezleri, özel Content-Security-Policy (CSP) ve SSRF filtreleme.

---

## 📜 Lisans

MIT License — Özgürce kullanabilir, değiştirebilir ve homelab sunucularınızda dağıtabilirsiniz.
