#pragma once

#include "connection.cpp"
#include "thread_pool.cpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

class ProxyServer {
public:
    ProxyServer(uint16_t    proxy_port,
                uint16_t    stats_port,
                size_t      num_threads,
                SslContext& ssl_ctx,
                Blocker&    blocker,
                Stats&      stats);
    ~ProxyServer();
    void run();
    void stop();
private:
    static int         create_listen_socket(uint16_t port);
    static std::string peer_ip(const struct sockaddr_storage& addr);
    void proxy_accept_loop();
    void stats_accept_loop();
    void handle_stats_request(int client_fd);

    uint16_t     proxy_port_;
    uint16_t     stats_port_;
    SslContext& ssl_ctx_;
    Blocker&    blocker_;
    Stats&      stats_;
    ThreadPool   pool_;

    int proxy_listen_fd_{-1};
    int stats_listen_fd_{-1};

    std::atomic<bool> running_{false};
    std::thread       stats_thread_;
};

// -----------------------------------------------------------------------------

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>

ProxyServer::ProxyServer(uint16_t    proxy_port,
                         uint16_t    stats_port,
                         size_t      num_threads,
                         SslContext& ssl_ctx,
                         Blocker&    blocker,
                         Stats&      stats)
    : proxy_port_(proxy_port),
      stats_port_(stats_port),
      ssl_ctx_(ssl_ctx),
      blocker_(blocker),
      stats_(stats),
      pool_(num_threads) {}

ProxyServer::~ProxyServer() {
    stop();
    if (proxy_listen_fd_ >= 0) ::close(proxy_listen_fd_);
    if (stats_listen_fd_ >= 0) ::close(stats_listen_fd_);
}

int ProxyServer::create_listen_socket(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(fd, 128) != 0) {
        ::close(fd); return -1;
    }
    return fd;
}

std::string ProxyServer::peer_ip(const struct sockaddr_storage& addr) {
    char buf[INET_ADDRSTRLEN] = "unknown";
    if (addr.ss_family == AF_INET)
        inet_ntop(AF_INET, &reinterpret_cast<const struct sockaddr_in*>(&addr)->sin_addr, buf, sizeof(buf));
    return buf;
}

void ProxyServer::run() {
    proxy_listen_fd_ = create_listen_socket(proxy_port_);
    if (proxy_listen_fd_ < 0) {
        std::cerr << "[ProxyServer] Failed to bind proxy port " << proxy_port_ << "\n";
        return;
    }
    stats_listen_fd_ = create_listen_socket(stats_port_);
    if (stats_listen_fd_ < 0) {
        std::cerr << "[ProxyServer] Failed to bind stats port " << stats_port_ << "\n";
        return;
    }
    running_ = true;
    std::cerr << "[ProxyServer] Proxy listening on port " << proxy_port_ << "\n";
    std::cerr << "[ProxyServer] Stats endpoint on port  " << stats_port_ << "\n";
    stats_thread_ = std::thread(&ProxyServer::stats_accept_loop, this);
    proxy_accept_loop();
    if (stats_thread_.joinable()) stats_thread_.join();
}

void ProxyServer::stop() {
    running_ = false;
    if (proxy_listen_fd_ >= 0) ::shutdown(proxy_listen_fd_, SHUT_RDWR);
    if (stats_listen_fd_ >= 0) ::shutdown(stats_listen_fd_, SHUT_RDWR);
    pool_.shutdown();
}

void ProxyServer::proxy_accept_loop() {
    while (running_) {
        struct sockaddr_storage addr{};
        socklen_t len = sizeof(addr);
        int fd = ::accept(proxy_listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), &len);
        if (fd < 0) { if (!running_) break; continue; }
        std::string ip = peer_ip(addr);
        pool_.submit([fd, ip, &ssl = ssl_ctx_, &bl = blocker_, &st = stats_]() mutable {
            Connection conn(fd, std::move(ip), ssl, bl, st);
            conn.handle();
        });
    }
}

void ProxyServer::stats_accept_loop() {
    while (running_) {
        int fd = ::accept(stats_listen_fd_, nullptr, nullptr);
        if (fd < 0) { if (!running_) break; continue; }
        pool_.submit([fd, this]() { handle_stats_request(fd); });
    }
}

void ProxyServer::handle_stats_request(int client_fd) {
    char req_buf[2048] = {};
    (void)::recv(client_fd, req_buf, sizeof(req_buf) - 1, 0);
    const std::string body = stats_.serve_stats_page();
    const std::string resp =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    ::send(client_fd, resp.c_str(), resp.size(), MSG_NOSIGNAL);
    ::close(client_fd);
}
