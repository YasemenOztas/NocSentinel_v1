# 🛡️ NocSentinel v1

**NocSentinel**, kurumsal ağlardaki uç nokta cihazlarını (Windows) gerçek zamanlı izleyen, siber güvenlik olaylarını çok vektörlü **SIEM korelasyonu (Yapay Zeka + Yerel Kural Motoru)** ile analiz eden, otonom müdahale (bant genişliği kısıtlama, ağ izolasyonu, oturum kilitleme) uygulayan ve ağ trafiğini **meta-sezgisel optimizasyon algoritmalarıyla** dinamik olarak yöneten uçtan uca bir **EDR / SIEM & Ağ Trafik Optimizasyon** platformudur.

---

## ✨ Temel Özellikler

### 1. 🔒 Çok Katmanlı İletişim ve Kriptografik Güvenlik
* **İkili (Binary) Özel Paket Protokolü (`CryptoHelper`):** İstemci ve sunucu arasındaki tüm MQTT verileri önce `MessagePack` ile ikili formata serileştirilir, `zlib` ile sıkıştırılır ve **AES-256-GCM** (SHA-256 anahtar türetmeli) ile şifrelenerek `[VERSION (1B) | NONCE (12B) | TAG (16B) | CIPHERTEXT]` yapısında iletilir.
* **Karşılıklı TLS (mTLS) ve Otomatik Sertifika Kaydı (CSR Enrollment):**
  * Kendi kendine yeten X.509 Root CA altyapısı (`certs/generate_certs.py`).
  * İstemciler ilk kurulumda `REGISTRATION_TOKEN` ile CSR (Certificate Signing Request) göndererek cihaza özel imzalı sertifikalarını (`client_<PC_NAME>.crt`) otomatik alır.
  * İptal edilen veya süresi dolan sertifikalar için standart **X.509 CRL (`ca.crl`)** listesi otomatik güncellenir.
* **Dinamik Cihaz Kimliği:** İstemciler `HOSTNAME_MAC` formatında (örn. `DESKTOP-AB12_0A1B2C3D4E5F`) benzersiz kimlik üretir; manuel konfigürasyon gerektirmez.

### 2. 🖥️ Uç Nokta İzleme ve EDR Ajanı (`client/`)
* **Süreç (Process) Gözlemcisi ve SHA-256 Hash Denetimi:**
  * Başlangıçta çalışan süreçlerin envanterini çıkarır ve yeni başlatılan her sürecin (`psutil`) SHA-256 özetini hesaplar.
  * PID yeniden kullanımına (PID Recycling) ve TOCTOU durumlarına karşı korumalı, LRU önbellekli (`FILE_HASH_CACHE`) mimari.
  * Sunucu tarafından senkronize edilen **Beyaz Liste (`scanned_hashes_cache.json`)** sayesinde güvenli bilinen uygulamalar için gereksiz ağ trafiği üretilmez.
* **Windows Security Event Log Gözlemcisi (`win32evtlog`):**
  * Kritik güvenlik olaylarını gerçek zamanlı yakalar ve yapısal olarak ayrıştırır:
    * **Günlük Sabotajı:** `1100` (Olay günlüğü servisi durduruldu), `1102` (Security denetim günlüğü silindi)
    * **Kimlik Doğrulama & Brute-Force:** `4624`, `4625` (Son 1 dakikadaki ardışık başarısız giriş takibi), `4634`, `4648`, `4672`, `4673`, `4674`
    * **Hesap ve Grup Manipülasyonu:** `4720` (Yeni kullanıcı), `4722`, `4725`, `4726` (Kullanıcı silme), `4732`/`4733` (`Administrators` grubuna üye ekleme/çıkarma), `4728`, `4729`, `4735`, `4737`, `4738`, `4740` (Hesap kilitlenmesi), `4756`, `4757`
    * **Kalıcılık (Persistence) & Politika:** `4697`, `7045` (Yeni servis kurulumu), `4698`, `4699`, `4702` (Zamanlanmış görevler), `4704`, `4719`, `4739`
  * Olay günlüğünün dışarıdan temizlenmesi durumunda `RecordNumber` sıfırlanmasını tespit ederek izlemeye kesintisiz devam eder.
* **Donanım Telemetri Ajanı:**
  * Sunucudan dinamik olarak ayarlanabilen periyotlarla CPU kullanımı (%), RAM kullanımı (%) ve CPU sıcaklığını (°C) raporlar; kritik eşik aşımlarında (`CPU > %90`, `RAM > %90`, `Sıcaklık > 80°C`) otomatik uyarı üretir.

### 3. 🧠 Hibrit SIEM Risk Motoru ve Otonom Müdahale (`server/risk_engine.py`)
* **Çok Vektörlü Yapay Zeka (LLM) Korelasyonu:**
  * OpenAI uyumlu API (varsayılan: **DeepSeek** `deepseek-chat`) üzerinden uç noktanın önem derecesini (`1-10`), anlık donanım telemetrisini, son 5 dakikalık olay geçmişini ve yeni gelen olayı birlikte değerlendirerek `0-100` arası kalibre edilmiş risk skoru ve Türkçe analiz gerekçesi üretir.
* **Kesintisiz Yerel Yedek (Fallback) Kural Motoru:**
  * İnternet/API erişimi olmadığında veya AI devre dışı bırakıldığında deterministik ağırlıklı formül, Redis tabanlı Brute-Force sayacı ve Event ID ceza matrisiyle sıfır kesintiyle karar verir.
* **Kapsam (Scope) Destekli Kara & Beyaz Liste:**
  * SHA-256 hash veya süreç adına göre **1) Cihaz Bazlı**, **2) Öncelik Seviyesi Bazlı**, **3) Global** hiyerarşide çalışan Kara Liste (`KaraListe`) ve Beyaz Liste (`BeyazListe`) denetimi.
* **Öncelik Politikaları ve 4 Kademeli Otonom Aksiyon:**
  * Her öncelik seviyesi (`1-10`) için ayrı eşik değerleri, karantina süreleri, minimum bant genişliği ve muafiyet (`auto_isolate_exempt`) tanımlanabilir:
    * `ALLOW`: Normal çalışma ve adil bant genişliği tahsisi.
    * `RESTRICT`: Token Bucket üzerinden istemcinin veri gönderim hızının (bant genişliğinin) kısıtlanması.
    * `ISOLATE`: Windows Gelişmiş Güvenlik Duvarı (`netsh advfirewall`) üzerinden istemcinin gelen/giden tüm ağ trafiğinin kesilmesi (sadece MQTT broker ve Admin API IP/portları açık bırakılır).
    * `LOCKDOWN`: Zararlı sürecin sonlandırılması (`taskkill /F`), iş istasyonu oturumunun anında kilitlenmesi (`LockWorkStation`) ve tam ağ izolasyonu.

### 4. 📊 Dinamik Bant Genişliği ve Trafik Optimizasyonu (`server/optimization/`)
Ağ kapasitesini istemcilerin öncelik seviyeleri, anlık talepleri, kuyruk gecikmeleri ve risk durumlarına göre gerçek zamanlı paylaştıran **6 farklı algoritma** içerir (Yönetim panelinden anlık değiştirilebilir):
1. **Genetik Algoritma (`GeneticOptimizer` - GA)**
2. **Parçacık Sürü Optimizasyonu (`PSOOptimizer` - PSO)**
3. **Yapay Arı Kolonisi (`ABCOptimizer` - ABC)**
4. **Tavlama Benzetimi (`SimulatedAnnealingOptimizer` - SA)**
5. **Oransal Adil Paylaşım (`ProportionalFairOptimizer` - PF)**
6. **Max-Min Fair Paylaşım (`MaxMinFairOptimizer` - MMF)**

* **Token Bucket Hız Sınırlayıcı (`token_bucket.py`):** Hem istemci hem sunucu tarafında atanmış Kbps limitlerini uygular; `client_create_ts` ve `client_send_ts` zaman damgalarıyla NTP senkronizasyonuna ihtiyaç duymadan gerçek kuyruk bekleme gecikmesini ölçer.

### 5. 🔄 Yüksek Erişilebilirlik (High Availability) ve Dayanıklılık
* **Çift Katmanlı Veritabanı Mimarisi (`PostgreSQL` + Otomatik `SQLite` Fallback):**
  * Ana veritabanı PostgreSQL'dir. Bağlantı koptuğunda sunucu otomatik olarak yerel `server_fallback.db` (SQLite) veritabanına geçer; PostgreSQL tekrar ayağa kalktığında `db_recovery` işçisi çevrimdışı kayıtları ana veritabanına senkronize eder.
* **Çift Katmanlı Kuyruk Mimarisi (`Redis` + Otomatik `In-Memory` Fallback):**
  * Öncelikli log ve telemetri kuyrukları Redis üzerinde çalışır. Redis kesintisinde bellek içi (In-Memory) öncelik kuyruğuna düşer ve `redis_reconnect` işçisi bağlantıyı otomatik kurtarır.
* **İstemci Çevrimdışı Önbelleği (`client/database.py`):**
  * Sunucu veya MQTT bağlantısı koptuğunda istemci tüm logları yerel SQLite veritabanında saklar, bağlantı kurulduğunda sırayla gönderir.
* **Arka Plan İşçileri (`server/workers/`) ve `ThreadSupervisor`:**
  * `queue_worker`, `telemetry`, `traffic`, `optimization`, `aging` (log öncelik yaşlandırma), `retention` (veri saklama süresi temizliği), `db_recovery` ve `redis_reconnect` işçileri çökmelere karşı `supervise_thread` ile korunur.

### 6. 🌐 Web Yönetim Paneli ve REST API (`server/admin_api.py` & `server/ui/`)
* **FastAPI + JWT Kimlik Doğrulama:** HS256 imzalı JWT token ve bellek sızıntısı korumalı Rate Limiter.
* **Canlı Gösterge Paneli (Dashboard):**
  * Cihaz envanteri, çevrimiçi/çevrimdışı durumu, anlık CPU/RAM/Sıcaklık metrikleri ve risk puanları.
  * Uzaktan manuel aksiyon gönderimi (`ALLOW`, `RESTRICT`, `ISOLATE`, `LOCKDOWN`, `RECOVER`).
  * Kara/Beyaz liste yönetimi, öncelik politikası matrisi (`1-10`), sertifika onay/iptal (CRL) yönetimi ve aktif optimizasyon algoritması seçimi.

---

## 📁 Proje Dizin Yapısı

```text
NocSentinel_v1/
├── .env.example                # Ortam değişkenleri şablonu
├── docker-compose.yml          # Redis ve Eclipse Mosquitto (MQTT) servis tanımları
├── requirements.txt            # Python bağımlılıkları
├── KURULUM_VE_CALISTIRMA.txt   # Detaylı kurulum ve dağıtım kılavuzu
│
├── certs/
│   └── generate_certs.py       # Root CA, Sunucu (SAN destekli) ve İstemci X.509 sertifika üretici
│
├── common/                     # İstemci ve Sunucu ortak çekirdek modülleri
│   ├── app_config.py           # Merkezi .env ve yapılandırma yöneticisi
│   ├── crypto_helper.py        # MessagePack + zlib + AES-256-GCM protokolü
│   ├── registry.py             # Servis içi geri çağırım (Callback) kayıt defteri
│   └── thread_supervisor.py    # Otomatik yeniden başlatmalı iş parçacığı denetleyicisi
│
├── config/
│   ├── docker-compose.yml      # Konfigürasyon dizini Docker tanımı
│   └── mosquitto.conf          # Mosquitto MQTT & TLS (8883) yapılandırması
│
├── client/                     # Uç Nokta (Windows) EDR & Telemetri Ajanı
│   ├── service_manager.py      # Windows Servis sarmalayıcısı (NocSentinelClient)
│   ├── sender_agent.py         # MQTT istemcisi, otonom aksiyon uygulayıcı (Firewall/Lockdown)
│   ├── monitors.py             # Süreç (SHA-256), Windows Security Event Log ve Telemetri izleyicileri
│   ├── certificate_manager.py  # Otomatik CSR üretimi ve sertifika kayıt yöneticisi
│   ├── database.py             # Çevrimdışı (Offline) SQLite log kuyruğu
│   ├── build_client.py         # PyInstaller ile tek dosya EXE derleme betiği
│   └── utils/                  # Yol, güvenlik ve Token Bucket yardımcı modülleri
│
└── server/                     # Merkezi SIEM, Risk Motoru ve Yönetim Sunucusu
    ├── windows_service.py      # Windows Servis sarmalayıcısı (NocSentinelServer)
    ├── receiver_server.py      # MQTT alıcısı, komut dağıtıcısı ve orkestratör
    ├── risk_engine.py          # AI (LLM) korelasyonu + yerel kural motoru
    ├── admin_api.py            # FastAPI tabanlı yönetim, kayıt (enrollment) ve izleme API'si
    ├── cert_enrollment.py      # CSR imzalama ve X.509 CRL üretimi
    ├── database.py             # SQLAlchemy modelleri (PostgreSQL + SQLite otomatik fallback)
    ├── token_bucket.py         # Sunucu tarafı trafik hız sınırlayıcı
    ├── build_server.py         # PyInstaller ile sunucu EXE derleme betiği
    ├── optimization/           # Bant genişliği optimizasyon algoritmaları (GA, PSO, ABC, SA, PF, MMF)
    ├── workers/                # Asenkron arka plan işçileri (Aging, Traffic, Recovery, Retention vb.)
    └── ui/                     # Web tabanlı yönetim arayüzü (HTML/CSS/JS)
```

---

## 🚀 Kurulum ve Çalıştırma

### 1. Ön Gereksinimler
* **İşletim Sistemi:** Windows 10 / 11 veya Windows Server (Windows Event Log, Güvenlik Duvarı ve Servis entegrasyonu için)
* **Python:** 3.10+ (Kaynak koddan çalıştırmak veya `.exe` derlemek için)
* **Docker Desktop:** Redis ve Eclipse Mosquitto (MQTT Broker) konteynerleri için
* **PostgreSQL** *(İsteğe bağlı)*: Kurulu değilse sistem otomatik olarak SQLite (`server_fallback.db`) ile çalışır.

### 2. Ortam Değişkenlerini (`.env`) Hazırlama
Proje kök dizinindeki `.env.example` dosyasını `.env` olarak kopyalayın ve değerleri düzenleyin:

```powershell
Copy-Item .env.example .env
```

```env
CRYPTO_SHARED_TOKEN=GucluBirPaylasilanAnahtarGirin
REGISTRATION_TOKEN=IstemciKayitTokeniGirin
NOC_ENV=production
MQTT_BROKER=192.168.1.50
MQTT_PORT=8883
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=root
USE_AI_ANALYSIS=true
AI_API_BASE=https://api.deepseek.com
AI_API_MODEL=deepseek-chat
AI_API_KEY=sk-...
```

> **Not:** İstemci makinelere dağıtılacak `.env` dosyasında yalnızca `CRYPTO_SHARED_TOKEN`, `REGISTRATION_TOKEN`, `MQTT_BROKER`, `MQTT_PORT` ve `NOC_ENV` satırlarının bulunması yeterlidir.

### 3. Kaynak Koddan Geliştirme Ortamında Çalıştırma

```powershell
# 1. Sanal ortamı oluşturun ve bağımlılıkları yükleyin
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt

# 2. TLS sertifikalarını üretin (certs/ klasörüne ca, server ve client sertifikalarını oluşturur)
cd certs
python generate_certs.py
cd ..

# 3. Redis ve Mosquitto servislerini başlatın
docker-compose up -d

# 4. Sunucuyu başlatın (Admin API: http://localhost:8000)
python server/receiver_server.py

# 5. İstemci ajanı başlatın (Yönetici haklarıyla açılmış ayrı bir terminalde)
python client/sender_agent.py
```

### 4. Bağımsız `.exe` (Windows Servisi) Olarak Derleme ve Dağıtım
Hedef bilgisayarlarda Python kurulu olmasına gerek kalmadan çalıştırmak için PyInstaller derleme betiklerini kullanabilirsiniz:

```powershell
# Sunucu paketini derle (Çıktı: server/dist/NocSentinelServer/ ve NocSentinel_Sunucu_EXE/)
python server/build_server.py

# İstemci paketini derle (Çıktı: client/dist/service_manager.exe ve NocSentinel_Istemci/)
python client/build_client.py
```

Derleme sonrasında:
* **Sunucu Kurulumu:** `deploy_server.bat` betiğini **Yönetici Olarak Çalıştır** seçeneğiyle başlatın (`NocSentinelServer.exe init` ile sertifikaları hazırlar, `8000` ve `8883` güvenlik duvarı kurallarını ekler, Docker servislerini ve Windows servisini başlatır).
* **İstemci Kurulumu:** `deploy_client.bat` betiğini istemci makinede **Yönetici Olarak Çalıştır** seçeneğiyle başlatın (`NocSentinelClient` servisini kurar ve arka planda başlatır).

---

## 🖥️ Yönetim Paneli
Sunucu çalıştığında tarayıcınızdan **`http://localhost:8000`** adresine giderek yönetim paneline erişebilirsiniz.
* Varsayılan giriş bilgileri `.env` üzerinden `ADMIN_USERNAME` ve `ADMIN_PASSWORD` değişkenleriyle yapılandırılır (varsayılan: `admin` / `admin123`).

