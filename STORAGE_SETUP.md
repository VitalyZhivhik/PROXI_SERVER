# Storage Setup

## Что реализовано

- `PostgreSQL` для модуля заявок на доступ в интернет из `shared/internet_access.py`
- `S3`/`MinIO` для хранения capture-файлов из `server/dlp_addon.py`
- Автоматический fallback:
  - если `database_url` не задан, используется JSON `logs/internet_access.json`
  - если `capture_storage` не равен `s3`, файлы сохраняются в `logs/captures`

## Что установить

### 1. Python-зависимости

```bash
pip install -r requirements.txt
```

### 2. PostgreSQL

Нужен запущенный сервер PostgreSQL и база данных, например:

```sql
CREATE DATABASE dlp_db;
CREATE USER dlp_user WITH PASSWORD 'strong_password';
GRANT ALL PRIVILEGES ON DATABASE dlp_db TO dlp_user;
```

### 3. S3-хранилище

Можно использовать:

- AWS S3
- MinIO
- Yandex Object Storage
- любой сервис с S3 API

Для локальной разработки удобно использовать `MinIO`.

## Настройки в `config.json`

Добавьте в `config.json`:

```json
{
  "database_url": "postgresql://dlp_user:strong_password@127.0.0.1:5432/dlp_db",
  "capture_storage": "s3",
  "capture_local_dir": "logs/captures",
  "s3_endpoint_url": "http://127.0.0.1:9000",
  "s3_bucket": "dlp-storage",
  "s3_access_key": "minioadmin",
  "s3_secret_key": "minioadmin",
  "s3_region": "us-east-1",
  "s3_use_ssl": false
}
```

## Переменные окружения

Вместо `config.json` можно использовать:

```bash
DLP_DATABASE_URL=
DLP_CAPTURE_STORAGE=
DLP_CAPTURE_LOCAL_DIR=
DLP_S3_ENDPOINT_URL=
DLP_S3_BUCKET=
DLP_S3_ACCESS_KEY=
DLP_S3_SECRET_KEY=
DLP_S3_REGION=
DLP_S3_USE_SSL=
```

## Примечание

- Таблицы для `internet_access` создаются автоматически при первом обращении к модулю.
- Если `boto3` установлен, но S3 недоступен, capture-файлы не будут доступны до восстановления S3.
- Следующий логичный шаг: перевести инциденты, уведомления и чат из JSON в PostgreSQL.
