#include "proxy_server.cpp"

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

static volatile sig_atomic_t g_shutdown = 0;
static void signal_handler(int /*sig*/) { g_shutdown = 1; }

struct Config {
    uint16_t    proxy_port   = 8080;
    uint16_t    stats_port   = 8888;
    size_t      threads      = 0;
    std::string blocklist    = "config/blocklist.txt";
    std::string ca_cert      = "config/ca.crt";
    std::string ca_key       = "config/ca.key";
};

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [OPTIONS]\n\n"
        << "Options:\n"
        << "  --port         <port>    Proxy listen port        (default: 8080)\n"
        << "  --stats-port   <port>    Stats HTTP endpoint port (default: 8888)\n"
        << "  --threads      <n>       Thread pool size         (default: nproc)\n"
        << "  --blocklist    <file>    Path to blocklist file   (default: config/blocklist.txt)\n"
        << "  --ca-cert      <file>    Path to CA certificate   (default: config/ca.crt)\n"
        << "  --ca-key       <file>    Path to CA private key   (default: config/ca.key)\n"
        << "  --help                   Show this message\n";
}

static Config parse_args(int argc, char* argv[]) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << "\n";
                std::exit(1);
            }
            return argv[++i];
        };
        if      (arg == "--help" || arg == "-h") { print_usage(argv[0]); std::exit(0); }
        else if (arg == "--port")         cfg.proxy_port   = static_cast<uint16_t>(std::stoi(next()));
        else if (arg == "--stats-port")   cfg.stats_port   = static_cast<uint16_t>(std::stoi(next()));
        else if (arg == "--threads")      cfg.threads      = static_cast<size_t>(std::stoi(next()));
        else if (arg == "--blocklist")    cfg.blocklist    = next();
        else if (arg == "--ca-cert")      cfg.ca_cert      = next();
        else if (arg == "--ca-key")       cfg.ca_key       = next();
        else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            std::exit(1);
        }
    }
    if (cfg.threads == 0)
        cfg.threads = std::max(1u, std::thread::hardware_concurrency());
    return cfg;
}

static void print_banner(const Config& cfg) {
    std::cerr
        << "============================================================\n"
        << "                    HTTPS MITM Proxy\n"
        << "============================================================\n"
        << "  Proxy port   : " << cfg.proxy_port   << "\n"
        << "  Stats port   : " << cfg.stats_port   << "\n"
        << "  Thread pool  : " << cfg.threads      << " thread(s)\n"
        << "  Blocklist    : " << cfg.blocklist    << "\n"
        << "  CA cert      : " << cfg.ca_cert      << "\n"
        << "  CA key       : " << cfg.ca_key       << "\n"
        << "------------------------------------------------------------\n"
        << "  Stats URL    : http://127.0.0.1:" << cfg.stats_port << "/\n"
        << "  Press Ctrl+C to stop.\n"
        << "============================================================\n";
}

int main(int argc, char* argv[]) {
    Config cfg = parse_args(argc, argv);
    print_banner(cfg);

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    SslContext ssl_ctx;
    if (!ssl_ctx.load_ca(cfg.ca_cert, cfg.ca_key)) {
        std::cerr << "[main] Failed to load CA credentials.\n"
                  << "       Run scripts/gen_ca.sh first.\n";
        return 1;
    }

    Blocker blocker;
    blocker.load(cfg.blocklist);

    Stats stats;

    ProxyServer server(cfg.proxy_port, cfg.stats_port, cfg.threads,
                       ssl_ctx, blocker, stats);

    std::thread server_thread([&server]() { server.run(); });

    while (!g_shutdown) ::pause();

    std::cerr << "\n[main] Shutdown signal received — stopping proxy...\n";
    server.stop();
    if (server_thread.joinable()) server_thread.join();
    std::cerr << "[main] Proxy stopped cleanly.\n";
    return 0;
}
