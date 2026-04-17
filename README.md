# DLP Proxy — Система защиты от утечки данных

## Структура проекта

```
dlp_proxy/
├── server/
│   ├── server_main.py      # Главный процесс сервера
│   ├── cert_manager.py     # Генерация CA сертификатов
│   └── dlp_addon.py        # mitmproxy DLP аддон
├── client/
│   ├── client_main.py      # PyQt6 GUI клиент
│   └── win_utils.py        # Windows: реестр, certutil
├── shared/
│   ├── dlp_rules.py        # DLP движок + правила
│   └── log_config.py       # Конфигурация логирования
├── build/
│   ├── server.spec         # PyInstaller spec для сервера
│   ├── client.spec         # PyInstaller spec для клиента
│   └── build_all.bat       # Скрипт сборки .exe
├── requirements.txt
└── README.md
```

## Быстрый старт

### 1. Установка зависимостей
```
pip install -r requirements.txt
```

### 2. Запуск сервера (Windows 11 — хостовая)
```
python server/server_main.py
```
Сервер запустит:
- HTTP сервер сертификатов на порту `8000`
- DLP прокси (mitmproxy) на порту `8080`

### 3. Запуск клиента (Windows 10 — VM, от Администратора)
```
python client/client_main.py
```
Введите IP хостовой машины, нажмите «Подключиться».
Клиент автоматически:
- Скачает CA сертификат с сервера
- Установит его в системное хранилище (certutil)
- Настроит системный прокси через реестр Windows

### 4. Сборка .exe
```
build\build_all.bat
```
 
## Логи
Все логи сохраняются в папке `logs/`:
- `server_YYYYMMDD.log` — события сервера
- `client_YYYYMMDD.log` — события клиента
- `proxy_YYYYMMDD.log` — события прокси
- `dlp_events.log` — все DLP блокировки (отдельный файл)

## DLP Правила
| Правило | Описание | Уровень |
|---------|----------|---------|
| ИНН | 10 или 12 цифр | ВЫСОКИЙ |
| СНИЛС | XXX-XXX-XXX XX | ВЫСОКИЙ |
| CARD_NUMBER | Номер карты 16 цифр | ВЫСОКИЙ |
| PASSPORT_RF | Серия + номер паспорта | ВЫСОКИЙ |
| PHONE_RU | +7 / 8 формат | СРЕДНИЙ |
| EMAIL | email адрес | СРЕДНИЙ |
| DSP_KEYWORDS | "для служебного пользования" и др. | ВЫСОКИЙ |

## Тестирование (Win11 хост ↔ Win10 VM)
1. Убедитесь, что VM в режиме сети **Host-only** или **Bridged**
2. Запустите `server_main.py` на хосте
3. Запустите `client_main.py` на VM **от Администратора**
4. Введите IP хоста (например `192.168.56.1`)
5. Нажмите «Подключиться»
6. Откройте браузер на VM — трафик пойдёт через DLP прокси

powershell -ExecutionPolicy Bypass -File .\install_cert_client.ps1
