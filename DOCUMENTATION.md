# Документация: HTTPS MITM Proxy
Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
proident, sunt in culpa qui officia deserunt mollit anim id est laborum.## Содержание

1. [Общая архитектура](#общая-архитектура)
2. [main.cpp](#maincpp)
3. [proxy_server.cpp](#proxy_servercpp)
4. [thread_pool.cpp](#thread_poolcpp)
5. [connection.cpp](#connectioncpp)
6. [ssl_context.cpp](#ssl_contextcpp)
7. [blocker.cpp](#blockercpp)
8. [stats.cpp](#statscpp)
9. [Поток данных](#поток-данных)
10. [Конкурентность и синхронизация](#конкурентность-и-синхронизация)

---


## Общая архитектура

Прокси реализован как многопоточный HTTPS MITM (Man-in-the-Middle) сервер. Браузер настраивается на использование прокси явно; без этой настройки прокси не перехватывает никакой трафик.

```
Браузер
  │
  │  HTTP CONNECT host:443
  ▼
ProxyServer (порт 8080)
  │
  │  accept() → ThreadPool::submit(task)
  ▼
Connection::handle()          ← выполняется в потоке из пула
  │
  ├── SslContext::get_server_ctx(host)  → генерирует leaf-сертификат
  ├── SSL_accept()                      → TLS handshake с браузером
  ├── connect_upstream()                → DNS + TCP + TLS к серверу
  ├── Blocker::is_blocked()             → проверка блокировки
  └── ssl_relay()                       → двунаправленная передача данных
        │
        └── Stats::record_request()     → запись статистики

ProxyServer (порт 8888)       ← отдельный поток
  └── handle_stats_request()  → JSON с текущей статистикой
```

### Структура файлов и зависимости

Все исходные файлы включают друг друга через `#include` и компилируются
как одна единица трансляции через `src/main.cpp`:

```
main.cpp
  └─ #include "proxy_server.cpp"
       ├─ #include "thread_pool.cpp"
       └─ #include "connection.cpp"
            ├─ #include "blocker.cpp"
            ├─ #include "ssl_context.cpp"
            └─ #include "stats.cpp"
```

---

## main.cpp

Точка входа программы. Отвечает за разбор аргументов командной строки,
инициализацию всех компонентов, обработку сигналов и корректное завершение.

### Структура `Config`

Хранит параметры запуска прокси.

| Поле | Тип | Значение по умолчанию | Описание |
|---|---|---|---|
| `proxy_port` | `uint16_t` | `8080` | Порт приёма клиентских подключений |
| `stats_port` | `uint16_t` | `8888` | Порт HTTP-эндпоинта статистики |
| `threads` | `size_t` | `0` (→ nproc) | Размер пула потоков |
| `blocklist` | `string` | `config/blocklist.txt` | Путь к файлу блокировок |
| `ca_cert` | `string` | `config/ca.crt` | Путь к CA-сертификату |
| `ca_key` | `string` | `config/ca.key` | Путь к CA-ключу |

### Функции

#### `parse_args(argc, argv) → Config`

Разбирает аргументы командной строки. Поддерживаемые флаги:

```
--port        <port>   Порт прокси
--stats-port  <port>   Порт статистики
--threads     <n>      Размер thread pool
--blocklist   <file>   Путь к blocklist
--ca-cert     <file>   Путь к CA-сертификату
--ca-key      <file>   Путь к CA-ключу
--help / -h            Вывод справки
```

Если `threads == 0` после разбора, устанавливается `std::thread::hardware_concurrency()`
(число логических ядер CPU), но не менее 1.

При неизвестном флаге — вывод справки и `exit(1)`.
При отсутствии значения после флага — сообщение об ошибке и `exit(1)`.

#### `print_banner(cfg)`

Выводит в `stderr` информационную шапку при старте:
порт прокси, порт статистики, число потоков, пути к файлам.

#### `main(argc, argv)`

Последовательность инициализации:

1. `parse_args()` — разбор CLI
2. `print_banner()` — вывод конфигурации
3. Настройка обработчиков сигналов:
   - `SIGINT` / `SIGTERM` → устанавливают `g_shutdown = 1`
   - `SIGPIPE` → `SIG_IGN` (игнорируется, чтобы запись в закрытый сокет не убивала процесс)
4. `SslContext::load_ca()` — загрузка CA-сертификата и ключа
5. `Blocker::load()` — загрузка списка блокировок
6. Создание `ProxyServer` и запуск в отдельном потоке
7. Главный поток: `while (!g_shutdown) ::pause()` — спит до сигнала
8. `server.stop()` + `server_thread.join()` — корректное завершение

---

## proxy_server.cpp

Управляет двумя циклами приёма соединений (прокси и статистика)
и раздаёт задачи в `ThreadPool`.

### Класс `ProxyServer`

#### Конструктор

```cpp
ProxyServer(uint16_t proxy_port, uint16_t stats_port, size_t num_threads,
            SslContext& ssl_ctx, Blocker& blocker, Stats& stats)
```

Сохраняет ссылки на все зависимости. Создаёт `ThreadPool` с `num_threads` потоками.
Сокеты не создаются — только при вызове `run()`.

#### `run()`

Основной метод запуска. Выполняется в отдельном потоке (`server_thread` в `main`).

1. Создаёт два слушающих сокета через `create_listen_socket()`
2. Устанавливает `running_ = true`
3. Запускает `stats_accept_loop()` в отдельном потоке (`stats_thread_`)
4. Сам входит в `proxy_accept_loop()` (блокируется здесь до `stop()`)
5. После выхода из `proxy_accept_loop()` ждёт `stats_thread_.join()`

#### `stop()`

Корректная остановка:

1. `running_ = false`
2. `shutdown(proxy_listen_fd_)` и `shutdown(stats_listen_fd_)` — разблокирует `accept()` в обоих циклах
3. `pool_.shutdown()` — ждёт завершения всех текущих задач

#### `create_listen_socket(port) → int` (static)

Создаёт TCP-сокет, настраивает `SO_REUSEADDR`, выполняет `bind()` и `listen(128)`.
Возвращает файловый дескриптор или `-1` при ошибке.

Очередь ожидания `listen(128)` — максимальное число соединений, ожидающих `accept()`.

#### `proxy_accept_loop()`

```
while (running_):
    client_fd = accept(proxy_listen_fd_)
    ip = peer_ip(client_addr)
    pool_.submit(lambda: Connection(client_fd, ip, ssl, blocker, stats).handle())
```

Каждое принятое соединение оборачивается в лямбду и передаётся в `ThreadPool`.
`Connection` создаётся внутри лямбды — уже в потоке пула, не в accept-потоке.

#### `stats_accept_loop()`

Аналогично `proxy_accept_loop()`, но для порта статистики.
Каждый запрос также обрабатывается через `pool_.submit()`.

#### `handle_stats_request(client_fd)`

Читает HTTP-запрос из сокета (содержимое не анализируется — любой запрос возвращает статистику).
Формирует HTTP-ответ:

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: <n>
Connection: close

<JSON от Stats::serve_stats_page()>
```

#### `peer_ip(addr) → string` (static)

Извлекает IPv4-адрес клиента из `sockaddr_storage` в строку через `inet_ntop()`.

---

## thread_pool.cpp

Реализует пул потоков с очередью задач и синхронизацией через `condition_variable`.

### Класс `ThreadPool`

#### Внутренние поля

| Поле | Тип | Описание |
|---|---|---|
| `workers_` | `vector<thread>` | Рабочие потоки |
| `task_queue_` | `queue<function<void()>>` | Очередь задач |
| `queue_mutex_` | `mutex` | Защита очереди |
| `cv_` | `condition_variable` | Оповещение воркеров |
| `stop_` | `bool` | Флаг остановки |

#### Конструктор `ThreadPool(num_threads)`

Создаёт `num_threads` потоков, каждый из которых выполняет `worker_loop()`.

`workers_.reserve(num_threads)` вызывается до создания потоков, чтобы не было
реаллокации вектора в процессе добавления потоков.

#### `submit(task)`

```cpp
void submit(std::function<void()> task)
```

1. Захватывает `queue_mutex_`
2. Кладёт задачу в очередь через `std::move`
3. Освобождает мьютекс
4. Вызывает `cv_.notify_one()` — будит один спящий воркер

`notify_one()` вызывается **вне** мьютекса — это правильно: воркер просыпается
и сразу может захватить мьютекс без лишнего ожидания.

#### `shutdown()`

1. Захватывает мьютекс, устанавливает `stop_ = true`
2. `cv_.notify_all()` — будит всех воркеров
3. `join()` для каждого потока — ждёт завершения

Воркеры при `stop_ == true` дочитывают оставшиеся задачи из очереди,
затем выходят (условие `stop_ && task_queue_.empty()`).

#### `worker_loop()`

```cpp
void worker_loop() {
    while (true) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        cv_.wait(lock, [this] { return stop_ || !task_queue_.empty(); });
        if (stop_ && task_queue_.empty()) return;
        auto task = std::move(task_queue_.front());
        task_queue_.pop();
        lock.unlock();
        task();  // выполняется вне мьютекса
    }
}
```

`cv_.wait(lock, predicate)` атомарно:
- Освобождает `lock`
- Переводит поток в спящий режим
- При `notify_one/all`: захватывает `lock`, проверяет предикат
- Если предикат `false` — снова засыпает (защита от spurious wakeup)

Задача извлекается и выполняется **вне мьютекса** — другие потоки могут
параллельно брать свои задачи.

---

## connection.cpp

Управляет полным жизненным циклом одного клиентского соединения.
Один экземпляр `Connection` — одно соединение — один поток пула.

### Класс `Connection`

#### Внутренние поля

| Поле | Тип | Описание |
|---|---|---|
| `client_fd_` | `int` | Сокет клиента (браузера) |
| `client_ip_` | `string` | IP клиента (для логов) |
| `ssl_ctx_` | `SslContext&` | Для получения SSL_CTX |
| `blocker_` | `Blocker&` | Для проверки блокировок |
| `stats_` | `Stats&` | Для записи статистики |
| `host_` | `string` | Хост из CONNECT-запроса |
| `port_` | `uint16_t` | Порт (обычно 443) |
| `client_ssl_` | `SSL*` | TLS-соединение с браузером |
| `upstream_ssl_` | `SSL*` | TLS-соединение с сервером |
| `upstream_fd_` | `int` | Сокет к серверу |
| `req_buf_` | `string` | Сырые HTTP-заголовки запроса |
| `method_` | `string` | HTTP-метод (GET, POST, ...) |
| `path_` | `string` | URL-путь |

#### Деструктор

Всегда освобождает ресурсы независимо от того, на каком шаге завершилась обработка:
- `SSL_free()` для обоих SSL-объектов (`SSL_free(nullptr)` — no-op, проверки не нужны)
- `close()` для обоих файловых дескрипторов

#### `handle()`

Главная функция — оркестрирует все фазы обработки соединения:

```
++stats_.active_connections

read_connect_request()   → извлечь host:port из CONNECT
send_connect_ok()        → ответить "200 Connection established"
ssl_handshake_client()   → TLS с браузером (leaf cert)
connect_upstream()       → DNS + TCP + TLS к серверу
read_http_request()      → прочитать HTTP-запрос (уже расшифрованный)
is_blocked(host, path)?  → если да: send_error(403), return
relay()                  → двунаправленный relay до закрытия соединения

--stats_.active_connections
```

При ошибке на любом шаге функция выходит, деструктор освобождает ресурсы.

#### `read_connect_request() → bool`

Читает и разбирает стартовую строку HTTP CONNECT:

```
CONNECT github.com:443 HTTP/1.1\r\n
Host: github.com:443\r\n
\r\n
```

1. `read_line()` — читает первую строку побайтово через `recv()`
2. Разбирает методом строковых потоков (`istringstream`): метод, `host:port`, версия
3. Проверяет что метод — `CONNECT` (иначе 405 Method Not Allowed)
4. Разделяет `host:port` по последнему `:` (на случай IPv6-адресов)
5. Дочитывает оставшиеся заголовки до пустой строки (не используются, но нужно вычитать)

Сохраняет `host_` и `port_` для дальнейших шагов.

#### `send_connect_ok() → bool`

Отправляет клиенту:
```
HTTP/1.1 200 Connection established\r\n\r\n
```

После этого клиент считает туннель установленным и начинает TLS handshake.

#### `ssl_handshake_client() → bool`

1. `SSL_new(ssl_ctx_.get_server_ctx(host_))` — создаёт SSL-объект с leaf-сертификатом для хоста
2. `SSL_set_fd(client_ssl_, client_fd_)` — привязывает к сокету
3. `SSL_accept(client_ssl_)` — выполняет серверный TLS handshake

Если браузер не доверяет CA — `SSL_accept` завершается с ошибкой
`unexpected eof while reading` (браузер закрывает соединение).

#### `connect_upstream() → bool`

Устанавливает соединение с реальным сервером:

1. `getaddrinfo(host_, port_)` — DNS-разрешение
2. `socket()` + `connect()` — TCP-соединение
3. `freeaddrinfo()` — освобождение результата DNS
4. `SSL_new(client_ctx_)` — SSL без верификации сертификата сервера
5. `SSL_set_tlsext_host_name()` — устанавливает SNI (Server Name Indication),
   без этого многие серверы не знают какой сертификат отдать
6. `SSL_connect()` — клиентский TLS handshake с сервером

`SSL_VERIFY_NONE` в `client_ctx_` означает что прокси принимает любой сертификат сервера,
включая самоподписанные и просроченные.

#### `read_http_request() → bool`

Читает HTTP-запрос через расшифрованное SSL-соединение с браузером.
Данные идут уже в открытом виде через `SSL_read()`.

Читает побайтово до `\r\n` для каждой строки. Сохраняет:
- Полный заголовочный блок в `req_buf_` (потребуется для пересылки на сервер)
- `method_`, `path_`, `http_version_` из первой строки

Завершается при чтении пустой строки (конец заголовков HTTP/1.x).

#### `relay()`

1. Пересылает сохранённые HTTP-заголовки (`req_buf_`) на upstream через `ssl_write_all()`
2. Запускает `ssl_relay()` для двунаправленной передачи тела и ответа
3. Записывает статистику: суммарные байты = `relay_bytes + req_buf_.size()`

#### `send_error(status_code, status_text, body)`

Формирует HTTP-ответ об ошибке. Учитывает состояние соединения:
- Если TLS с клиентом уже установлен → использует `ssl_write_all()`
- Если нет (ошибка до handshake) → использует `write_all()`

#### `ssl_relay(client_ssl, upstream_ssl) → uint64_t` (static)

Двунаправленная передача данных между двумя TLS-соединениями.
Возвращает суммарное число переданных байт.

```cpp
while (!client_eof || !upstream_eof) {
    // Проверяем SSL_pending перед poll() — OpenSSL мог расшифровать
    // данные во внутренний буфер, но на уровне сокета нет новых байт.
    if (SSL_pending(client_ssl) == 0 && SSL_pending(upstream_ssl) == 0)
        poll(fds, nfds, 30000 /*мс*/);

    // Клиент → сервер
    if (SSL_pending(client_ssl) > 0 || fd_ready(client_fd))
        n = SSL_read(client_ssl, buf, BUF_SIZE)
        ssl_write_all(upstream_ssl, buf, n)

    // Сервер → клиент
    if (SSL_pending(upstream_ssl) > 0 || fd_ready(upstream_fd))
        n = SSL_read(upstream_ssl, buf, BUF_SIZE)
        ssl_write_all(client_ssl, buf, n)
}
```

`poll()` с таймаутом 30 секунд: если 30 секунд нет данных ни с одной стороны —
соединение считается мёртвым и закрывается.

Буфер 16 КБ (`BUF_SIZE = 16 * 1024`) — типичный размер TLS-записи.

#### `read_line(fd, out, max_len) → bool` (static)

Читает одну строку из сокета побайтово через `recv()`.
Убирает завершающий `\r` если есть. Возвращает `true` при успехе.

Побайтовое чтение неэффективно для больших объёмов, но для HTTP-заголовков
(сотни байт) это несущественно.

#### `write_all(fd, buf, len) → bool` (static)

Гарантирует запись всех `len` байт в сокет, повторяя `send()` если нужно.
`MSG_NOSIGNAL` предотвращает сигнал `SIGPIPE` при записи в закрытый сокет.

#### `ssl_write_all(ssl, buf, len) → bool` (static)

Аналог `write_all()` для SSL-соединения через `SSL_write()`.

---

## ssl_context.cpp

Управляет CA-сертификатом, генерирует leaf-сертификаты для каждого хоста
и кеширует их для повторного использования.

### Класс `SslContext`

#### Внутренние поля

| Поле | Тип | Описание |
|---|---|---|
| `ca_cert_` | `X509*` | Загруженный CA-сертификат |
| `ca_key_` | `EVP_PKEY*` | Загруженный CA-ключ |
| `ctx_cache_` | `unordered_map<string, SSL_CTX*>` | Кеш leaf-контекстов по хосту |
| `cache_mutex_` | `shared_mutex` | RW-мьютекс для кеша |
| `client_ctx_` | `SSL_CTX*` | Контекст для исходящих TLS (без верификации) |

#### Деструктор

Освобождает все накопленные ресурсы: `SSL_CTX_free()` для каждого элемента кеша
и для `client_ctx_`, `X509_free(ca_cert_)`, `EVP_PKEY_free(ca_key_)`.
Все эти функции безопасно принимают `nullptr` — явные проверки не нужны.

#### `load_ca(cert_path, key_path) → bool`

Загружает CA-материалы из PEM-файлов:

1. `BIO_new_file(cert_path, "r")` → `PEM_read_bio_X509()` — читает сертификат
2. `BIO_new_file(key_path, "r")` → `PEM_read_bio_PrivateKey()` — читает ключ
3. Создаёт `client_ctx_` методом `TLS_client_method()` — для исходящих соединений
4. `SSL_CTX_set_verify(client_ctx_, SSL_VERIFY_NONE)` — не проверять сертификат сервера

BIO (Basic I/O) — абстракция ввода-вывода OpenSSL. Оборачивается в `unique_ptr`
с кастомным deleter для гарантированного освобождения.

#### `get_server_ctx(hostname) → SSL_CTX*`

```cpp
std::unique_lock<std::shared_mutex> lock(cache_mutex_);
SSL_CTX*& ctx = ctx_cache_[hostname];
if (!ctx) ctx = generate_leaf_ctx(hostname);
return ctx;
```

`unique_lock` на `shared_mutex` — монопольный доступ. `operator[]` возвращает ссылку:
если хост уже в кеше — возвращаем готовый контекст, иначе генерируем новый.

#### `get_client_ctx() → SSL_CTX*`

Возвращает общий клиентский контекст для всех исходящих TLS-соединений.
Thread-safe: создаётся один раз в `load_ca()`, потом только читается.

#### `generate_leaf_ctx(hostname) → SSL_CTX*` (private)

Создаёт полный `SSL_CTX` для хоста:

1. `generate_rsa_key(2048)` — новый RSA-ключ для leaf
2. `generate_leaf_cert(hostname, ca_cert_, ca_key_, leaf_key)` — сертификат
3. `SSL_CTX_new(TLS_server_method())` — новый серверный контекст
4. `SSL_CTX_use_certificate()` + `SSL_CTX_use_PrivateKey()` — установка сертификата и ключа
5. `SSL_CTX_add_extra_chain_cert(X509_dup(ca_cert_))` — добавление CA в цепочку

Добавление CA в цепочку важно: браузер получает и leaf, и промежуточный CA
за один handshake, что ускоряет проверку.

#### `generate_rsa_key(bits) → EVP_PKEY*` (static)

Генерирует RSA-ключ через современный EVP API:

```cpp
EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
EVP_PKEY_keygen_init(kctx);
EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, bits);
EVP_PKEY* pkey = nullptr;
EVP_PKEY_keygen(kctx, &pkey);
EVP_PKEY_CTX_free(kctx);
return pkey;
```

#### `generate_leaf_cert(hostname, ca_cert, ca_key, leaf_key) → X509*` (static)

Создаёт X.509 v3 сертификат:

| Поле | Значение | Назначение |
|---|---|---|
| Version | 3 (значение 2 в API) | Версия X.509 |
| SerialNumber | `std::time(nullptr)` | Уникальность через текущее время |
| NotBefore | сейчас | Начало действия |
| NotAfter | сейчас + 1 год | Конец действия |
| Subject CN | hostname | Имя сервера |
| Issuer | Subject Name CA | Кто подписал |
| SAN | `DNS:hostname` | Subject Alternative Name — главное поле для браузеров |
| BasicConstraints | `CA:FALSE` | Это не CA-сертификат |
| KeyUsage | `digitalSignature, keyEncipherment` | Разрешённые операции |
| ExtKeyUsage | `serverAuth` | Назначение — аутентификация сервера |

Подпись: `X509_sign(cert, ca_key, EVP_sha256())` — SHA-256 с RSA.

SAN (`subjectAltName`) обязателен: современные браузеры игнорируют `CN` и смотрят только на SAN.

---

## blocker.cpp

Загружает и проверяет список заблокированных доменов и URL-префиксов.

### Класс `Blocker`

#### Внутренние поля

| Поле | Тип | Описание |
|---|---|---|
| `blocked_domains_` | `unordered_set<string>` | Полные домены для блокировки |
| `blocked_url_prefixes_` | `vector<pair<string,string>>` | Пары (хост, префикс-пути) |

`unordered_set` — O(1) поиск по хешу для доменов.
`vector` — линейный перебор для URL-префиксов (их обычно мало).

#### `load(filepath) → bool`

Читает файл построчно:
- Пустые строки и строки начинающиеся с `#` — пропускаются
- Каждая строка приводится к нижнему регистру через `to_lower()`
- Если строка содержит `/` — разделяется на хост и префикс пути → `blocked_url_prefixes_`
- Иначе → `blocked_domains_`

Пример разбора строки `cdn.example.com/ads`:
```
slash_pos = 15
host   = "cdn.example.com"
prefix = "/ads"
```

#### `is_blocked(host, path) → bool`

```cpp
lhost = to_lower(host);
lpath = to_lower(path);

if (blocked_domains_.count(lhost)) return true;   // O(1)

for (auto& [bhost, bprefix] : blocked_url_prefixes_)
    if (lhost == bhost && lpath.rfind(bprefix, 0) == 0)  // starts_with
        return true;

return false;
```

`rfind(bprefix, 0) == 0` — способ проверить что строка начинается с префикса
(эквивалент `starts_with` из C++20, которого нет в C++17).

#### Вспомогательные функции (file-scope)

`to_lower(s)` — приводит строку к нижнему регистру через `std::transform` + `std::tolower`.

`trim(s)` — убирает пробелы, табы, `\r`, `\n` с обоих концов строки.

---

## stats.cpp

Потокобезопасный сбор и сериализация статистики.

### Структура `DomainStats`

Статистика по одному домену. Все поля — `std::atomic<uint64_t>` для
lock-free инкремента из нескольких потоков.

```cpp
struct DomainStats {
    atomic<uint64_t> requests{0};
    atomic<uint64_t> bytes{0};
    atomic<uint64_t> blocked{0};
};
```

`unordered_map` использует node-based хранение — элементы не копируются при rehash,
поэтому copy-конструктор не нужен.

### Класс `Stats`

#### Публичные поля

```cpp
atomic<uint64_t> total_requests{0};
atomic<uint64_t> total_bytes{0};
atomic<uint64_t> total_blocked{0};
atomic<uint64_t> active_connections{0};
```

Глобальные счётчики — атомарные, без мьютекса.

#### Внутренние поля

```cpp
mutable shared_mutex domain_mutex_;
unordered_map<string, DomainStats> domain_stats_;
```

`mutable` — позволяет захватывать `shared_lock` в `const`-методах (например `serve_stats_page()`).

#### `get_domain(domain) → DomainStats&` (private)

```cpp
std::unique_lock<std::shared_mutex> lock(domain_mutex_);
return domain_stats_[domain];
```

`operator[]` с `unique_lock` — безопасно создаёт новый элемент при первом обращении к домену.

#### `record_request(domain, bytes, is_blocked)`

Вызывается из `Connection::handle()` в конце каждого соединения:

```cpp
++total_requests;           // атомарно
total_bytes += bytes;       // атомарно
if (is_blocked) ++total_blocked;

DomainStats& ds = get_domain(domain);
++ds.requests;
ds.bytes += bytes;
if (is_blocked) ++ds.blocked;
```

#### `serve_stats_page() → string`

Сериализует статистику в JSON. Берёт `shared_lock` на `domain_mutex_`
(несколько потоков могут читать одновременно) и итерирует по `domain_stats_`.

Формат ответа:

```json
{
  "timestamp": "2026-05-17T12:00:00Z",
  "global": {
    "total_requests": 49,
    "total_bytes": 183291,
    "total_blocked": 7,
    "active_connections": 2
  },
  "domains": {
    "github.com": {"requests": 42, "bytes": 183291, "blocked": 0},
    "doubleclick.net": {"requests": 7, "bytes": 0, "blocked": 7}
  }
}
```

---

## Поток данных

### HTTPS-запрос от начала до конца

```
1. Браузер отправляет:
   CONNECT github.com:443 HTTP/1.1\r\n
   Host: github.com\r\n
   \r\n

2. Прокси отвечает:
   HTTP/1.1 200 Connection established\r\n\r\n

3. Браузер начинает TLS handshake.
   Прокси вызывает SSL_accept() — предъявляет leaf-сертификат github.com,
   подписанный локальным CA.
   Браузер проверяет: CA в доверенных → handshake успешен.

4. Прокси подключается к реальному github.com:443 через TCP + TLS.
   SSL_set_tlsext_host_name() → SNI → github.com отдаёт свой настоящий сертификат.
   Прокси принимает любой сертификат (SSL_VERIFY_NONE).

5. Браузер отправляет HTTP-запрос через установленный TLS:
   GET /anthropics/claude-code HTTP/1.1\r\n
   Host: github.com\r\n
   ...

6. Прокси читает это через SSL_read() (данные уже расшифрованы).
   Проверяет Blocker: github.com не заблокирован.

7. Прокси пересылает заголовки запроса на upstream через SSL_write().
   Затем ssl_relay() гоняет данные в обе стороны до закрытия соединения.

8. Stats::record_request() фиксирует запрос.
```

### Blocked-запрос

```
1-5. Аналогично выше.

6. Blocker::is_blocked("doubleclick.net", "/") → true.

7. send_error(403, "Forbidden", "...") через SSL_write() на клиента.
   Stats::record_request("doubleclick.net", 0, true).

   Соединение с upstream не устанавливается вовсе.
```

---

## Конкурентность и синхронизация

### Схема блокировок

| Ресурс | Механизм | Кто читает | Кто пишет |
|---|---|---|---|
| `SslContext::ctx_cache_` | `shared_mutex` (unique_lock) | Все соединения | Первый запрос к новому хосту |
| `Stats::domain_stats_` | `shared_mutex` | `serve_stats_page()` | `record_request()` |
| `Stats::total_*` | `atomic` | `serve_stats_page()` | `record_request()` |
| `Stats::active_connections` | `atomic` | `serve_stats_page()` | `Connection::handle()` |
| `ThreadPool::task_queue_` | `mutex` + `cv` | `worker_loop()` | `submit()` |

### Почему `active_connections` атомарный, а не под мьютексом

`++` и `--` на `atomic<uint64_t>` — одна инструкция процессора (`lock xadd`).
Мьютекс для этого избыточен: он нужен когда несколько операций должны быть атомарны вместе.
Здесь каждый инкремент/декремент независим — атомик достаточен.
