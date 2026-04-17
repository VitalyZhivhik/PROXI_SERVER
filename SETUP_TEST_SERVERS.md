# Тестирование DLP — HTTPS сервисы в закрытой сети

## Схема тестирования

```
Win10 VM (клиент)          Win11 хост (сервер)
  браузер                    ┌──────────────────┐
    │                        │  DLP Proxy :8080  │
    ├──── HTTPS ────────────▶│  (mitmproxy)      │
    │  (через прокси)        │       │           │
    │                        │       ▼           │
    │                        │  Flask :9443      │ ← test_server_https.py
    │                        │  Nextcloud :8443  │ ← Docker
    │                        └──────────────────┘
```

Весь HTTPS-трафик с VM проходит через mitmproxy на порту 8080,
который расшифровывает, анализирует DLP-правилами и пропускает/блокирует.

---

## 1. Flask HTTPS Test Server (быстрый старт — 1 минута)

### Установка

```powershell
pip install flask cryptography
```

### Запуск

```powershell
python test_server_https.py
```

Сервер запустится на `https://IP_ХОСТА:9443`

### Что внутри

| Страница | URL | Что тестирует |
|----------|-----|---------------|
| Главная | `/` | Описание сценариев |
| Загрузка | `/upload` | multipart file upload → DLP анализирует |
| Скачивание | `/download` | file download → DLP фиксирует |
| Текст | `/text` | POST form → DLP проверяет тело |
| API | `/api-test` | JSON POST → DLP проверяет JSON |
| Журнал | `/log` | Все события на сервере |

### Тестовые файлы (создаются автоматически)

- `clean_report.txt` → DLP **пропустит** ✅
- `confidential_personal.txt` → DLP **заблокирует** 🚫 (ФИО + паспорт + СНИЛС)
- `payment_data.txt` → DLP **заблокирует** 🚫 (ИНН + карта + р/с)
- `dsp_document.txt` → DLP **заблокирует** 🚫 (гриф «совершенно секретно»)

### Как тестировать

1. На **хосте** (Win11): `python test_server_https.py`
2. На **VM** (Win10): откройте `https://192.168.x.x:9443`
3. Перейдите на «Скачать» → скачайте `confidential_personal.txt`
4. Перейдите на «Загрузить» → загрузите этот файл обратно
5. В админ-панели DLP (`http://IP:8000/admin/`) увидите блокировку

---

## 2. Nextcloud HTTPS (Docker — 5 минут)

### Требования

- Docker Desktop для Windows (скачать: https://docker.com)
- Docker Desktop должен быть **запущен**

### Установка

```powershell
cd nextcloud
powershell -ExecutionPolicy Bypass -File .\setup_nextcloud.ps1
```

Или вручную:

```powershell
cd nextcloud

# Создать папку для сертификатов
mkdir certs

# Сгенерировать сертификат (через Docker)
docker run --rm -v "${PWD}/certs:/certs" alpine/openssl `
    req -x509 -newkey rsa:2048 `
    -keyout /certs/server.key -out /certs/server.crt `
    -days 365 -nodes `
    -subj "/CN=DLP Nextcloud/O=DLP Test/C=RU"

# Запустить
docker-compose up -d
```

### Доступ

- URL: `https://IP_ХОСТА:8443`
- Логин: `admin`
- Пароль: `admin123`
- Первый запуск ~1-2 минуты (инициализация БД)

### Как тестировать

1. На VM откройте `https://192.168.x.x:8443`
2. Войдите admin / admin123
3. Нажмите «+» → «Upload file»
4. Загрузите файл с конфиденциальными данными
5. DLP перехватит HTTPS-трафик и заблокирует передачу

### Управление

```powershell
docker-compose logs -f      # Логи
docker-compose down          # Остановить
docker-compose up -d         # Запустить снова
docker-compose down -v       # Удалить с данными
```

---

## Важно: настройка DLP-прокси

Чтобы DLP перехватывал HTTPS трафик к тестовым серверам,
эти хосты **НЕ должны** быть в списке `IGNORE_HOSTS_REGEX` в `server_main.py`.

Проверьте, что IP хоста и порты 9443, 8443 **не исключены** из перехвата.
По умолчанию mitmproxy перехватывает всё, кроме явно указанных доменов.

Поскольку тестовые серверы работают по IP-адресу (а не по домену),
и IP хоста добавлен в bypass (чтобы клиент мог достучаться до порта 8000),
нужно убедиться, что bypass настроен **только** для порта 8000:

В `server_main.py` строка в `ProxyServer.start()`:
```python
cmd += ["--ignore-hosts", _escaped_host + ":" + str(self.cert_port)]
```

Это исключает только `IP:8000`. Порты 9443 и 8443 будут перехватываться.

---

## Порты (сводка)

| Порт | Сервис | Протокол |
|------|--------|----------|
| 8000 | DLP Admin + Cert Server | HTTP |
| 8080 | DLP Proxy (mitmproxy) | HTTP Proxy |
| 9443 | Flask Test Server | HTTPS |
| 8443 | Nextcloud (nginx) | HTTPS |

## Firewall

На хосте (Win11) откройте порты в Windows Firewall:

```powershell
netsh advfirewall firewall add rule name="DLP Flask Test" dir=in action=allow protocol=TCP localport=9443
netsh advfirewall firewall add rule name="DLP Nextcloud" dir=in action=allow protocol=TCP localport=8443
```
