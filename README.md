# HTTPS MITM Proxy

Перехватывает зашифрованный HTTPS-трафик, динамически генерирует TLS-сертификаты, блокирует домены и собирает статистику.

## Возможности

- **SSL/TLS MITM** — расшифровывает HTTPS через динамическую генерацию leaf-сертификатов, подписанных локальным CA
- **Блокировка** — запрещает домены и URL-префиксы, возвращает HTTP 403
- **Статистика** — счётчики запросов, байт и блокировок по доменам; JSON-endpoint
- **Thread pool** — фиксированный пул потоков на `condition_variable`, каждое соединение — отдельная задача

## Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                        ProxyServer                          │
│   accept loop ──► ThreadPool ──► Connection::handle()       │
│   stats loop  ──► HTTP /  (port 8888)                       │
└─────────────────────────────────────────────────────────────┘

Connection::handle() — 8 фаз:
  1. Читает HTTP CONNECT host:port
  2. Отправляет "200 Connection established"
  3. SSL-bump клиента (SslContext → leaf cert для хоста)
  4. Открывает TCP + TLS к upstream
  5. Читает первый HTTP-запрос (метод, path)
  6. Проверяет blocklist (Blocker)  → 403 если заблокирован
  7. Двунаправленный relay через poll()
  8. Записывает статистику (Stats)
```

### Модули

| Файл | Описание |
|---|---|
| `src/main.cpp` | Разбор аргументов, инициализация компонентов, обработка сигналов |
| `src/proxy_server.cpp` | Accept loop, запуск thread pool, stats endpoint |
| `src/thread_pool.cpp` | Пул потоков: `submit(task)`, `condition_variable`, `shutdown()` |
| `src/ssl_context.cpp` | Загрузка CA, генерация leaf-сертификатов, кеш по хосту |
| `src/connection.cpp` | Полный жизненный цикл одного соединения |
| `src/blocker.cpp` | Blocklist: точное совпадение домена + совпадение URL-префикса |
| `src/stats.cpp` | Атомарные счётчики, сериализация в JSON |

## Сборка

**Зависимости:**
```bash
# Debian / Ubuntu
sudo apt install cmake g++ libssl-dev
```

**Первая сборка:**
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

**Пересборка после изменений:**
```bash
cd build && make -j$(nproc)
```

**Очистка артефактов сборки:**
```bash
# Удалить только объектники и бинарник (cmake-кэш сохранится)
cd build && make clean

# Полная очистка (следующий раз нужно снова cmake ..)
rm -rf build/
```

Бинарник: `build/proxy_server`

## Запуск

### 1. Генерация CA (один раз)

```bash
bash scripts/gen_ca.sh
# Создаёт config/ca.key и config/ca.crt
```

### 2. Установка CA в браузер

Добавьте `config/ca.crt` как доверенный корневой центр сертификации:

- **Firefox:** Настройки → Конфиденциальность → Сертификаты → Импорт
- **Chrome / Chromium:** Настройки → Безопасность → Управление сертификатами → Authorities → Import
- **Linux (системный стор):**
  ```bash
  sudo cp config/ca.crt /usr/local/share/ca-certificates/proxy-ca.crt
  sudo update-ca-certificates
  ```

### 3. Запуск прокси

```bash
./build/proxy_server
```

```
============================================================
  HTTPS MITM Proxy  —  Operating Systems & Networks Course
============================================================
  Proxy port   : 8080
  Stats port   : 8888
  Thread pool  : 8 thread(s)
  Blocklist    : config/blocklist.txt
------------------------------------------------------------
  Stats URL    : http://127.0.0.1:8888/
  Press Ctrl+C to stop.
============================================================
```

### 4. Настройка браузера

Укажите HTTP/HTTPS прокси: `127.0.0.1:8080`

### 5. Статистика

```bash
curl http://127.0.0.1:8888/
```

```json
{
  "timestamp": "2026-05-04T19:00:00Z",
  "global": {
    "total_requests": 49,
    "total_bytes": 183291,
    "total_blocked": 7,
    "active_connections": 2
  },
  "domains": {
    "github.com":       {"requests": 42, "bytes": 183291, "blocked": 0},
    "doubleclick.net":  {"requests": 7,  "bytes": 0,      "blocked": 7}
  }
}
```

### 6. Остановка

`Ctrl+C` — прокси завершается корректно: дожидается окончания активных соединений, останавливает thread pool.

## Опции командной строки

```
--port         <port>   Порт прокси              (по умолчанию: 8080)
--stats-port   <port>   Порт статистики           (по умолчанию: 8888)
--threads      <n>      Размер thread pool        (по умолчанию: nproc)
--blocklist    <file>   Путь к blocklist-файлу    (по умолчанию: config/blocklist.txt)
--ca-cert      <file>   Путь к CA-сертификату     (по умолчанию: config/ca.crt)
--ca-key       <file>   Путь к CA-ключу           (по умолчанию: config/ca.key)
```

## Формат blocklist

Файл `config/blocklist.txt`:

```
# Комментарии начинаются с #
# Блокировать весь домен:
doubleclick.net
ads.example.com

# Блокировать только конкретный URL-префикс:
cdn.example.com/ads
static.example.org/banners
```

## Технические детали

### Thread pool

```
submit(task) → task_queue_ (mutex + cv) → worker_1..N → Connection::handle()

shutdown(): stop_=true → notify_all() → join all
```

Воркеры блокируются на `condition_variable::wait()`, просыпаются по `notify_one()` при добавлении задачи.

### SSL/TLS MITM

```
Браузер ──[CONNECT github.com:443]──► Прокси
Прокси  ──[200 Connection established]──► Браузер
Прокси  ──[TLS handshake, cert: github.com signed by CA]──► Браузер
Прокси  ──[TCP + TLS handshake]──► github.com
Браузер ◄──[двунаправленный SSL relay]──► github.com
```

Leaf-сертификат генерируется один раз на домен (RSA 2048 бит, SAN extension) и кешируется в `std::unordered_map<string, SSL_CTX*>` с `std::shared_mutex`.

### Relay

Двунаправленный relay реализован через `poll()` на оба сокета одновременно — без отдельных потоков на направление. `SSL_pending()` проверяется до `poll()`, чтобы не потерять данные, уже буферизованные внутри OpenSSL.

## Требования

- C++17
- OpenSSL ≥ 1.1.1
- CMake ≥ 3.14
- POSIX (Linux / macOS)
