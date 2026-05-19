#pragma once

#include "blocker.cpp"
#include "ssl_context.cpp"
#include "stats.cpp"

#include <openssl/ssl.h>
#include <string>

class Connection {
public:
    Connection(int         client_fd,
               std::string client_ip,
               SslContext& ssl_context,
               Blocker&    blocker,
               Stats&      stats);
    ~Connection();
    void handle();
private:
    bool read_connect_request();
    bool send_connect_ok();
    bool ssl_handshake_client();
    bool connect_upstream();
    bool read_http_request();
    void relay();
    void send_error(int status_code, const char* status_text, const char* body);

    static bool     read_line(int fd, std::string& out, size_t max_len = 8192);
    static bool     write_all(int fd, const char* buf, size_t len);
    static bool     ssl_write_all(SSL* ssl, const char* buf, size_t len);
    static uint64_t ssl_relay(SSL* client_ssl, SSL* upstream_ssl);

    int          client_fd_;
    std::string  client_ip_;
    SslContext& ssl_ctx_;
    Blocker&    blocker_;
    Stats&      stats_;

    std::string host_;
    uint16_t    port_{443};

    SSL* client_ssl_{nullptr};
    SSL* upstream_ssl_{nullptr};
    int  upstream_fd_{-1};

    std::string req_buf_;
    std::string method_;
    std::string path_;
};

// -----------------------------------------------------------------------------

#include <openssl/err.h>

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ctime>
#include <iostream>
#include <sstream>
#include <vector>

static std::string conn_timestamp() {
    std::time_t t = std::time(nullptr);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
    return buf;
}

#define LOG(msg) std::cerr << "[" << conn_timestamp() << "] " << msg << "\n"

static bool ssl_read_line(SSL* ssl, std::string& out) {
    out.clear();
    char ch;
    while (out.size() < 8192) {
        if (SSL_read(ssl, &ch, 1) <= 0) return false;
        if (ch == '\n') {
            if (!out.empty() && out.back() == '\r') out.pop_back();
            return true;
        }
        out += ch;
    }
    return false;
}

Connection::Connection(int         client_fd,
                       std::string client_ip,
                       SslContext& ssl_context,
                       Blocker&    blocker,
                       Stats&      stats)
    : client_fd_(client_fd),
      client_ip_(std::move(client_ip)),
      ssl_ctx_(ssl_context),
      blocker_(blocker),
      stats_(stats) {}

Connection::~Connection() {
    SSL_free(client_ssl_);
    SSL_free(upstream_ssl_);
    if (upstream_fd_ >= 0) ::close(upstream_fd_);
    if (client_fd_   >= 0) ::close(client_fd_);
}

void Connection::handle() {
    ++stats_.active_connections;
    struct Guard { Stats& s; ~Guard() { --s.active_connections; } } _guard{stats_};

    if (!read_connect_request()) return;

    if (blocker_.is_blocked(host_, "/")) {
        LOG("Blocked (CONNECT): " << client_ip_ << " -> " << host_);
        constexpr char resp[] =
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
            "Content-Length: 34\r\nConnection: close\r\n\r\n"
            "This site is blocked by the proxy.";
        write_all(client_fd_, resp, sizeof(resp) - 1);
        stats_.record_request(host_, 0, true);
        return;
    }

    if (!send_connect_ok())      return;
    if (!ssl_handshake_client()) return;

    if (!connect_upstream()) {
        send_error(502, "Bad Gateway", "Could not connect to upstream server.");
        stats_.record_request(host_, 0, false);
        return;
    }

    if (!read_http_request()) return;

    if (blocker_.is_blocked(host_, path_)) {
        LOG("Blocked: " << client_ip_ << " -> " << host_ << path_);
        send_error(403, "Forbidden", "This URL has been blocked by the proxy administrator.");
        stats_.record_request(host_, 0, true);
        return;
    }

    LOG("Relay: " << client_ip_ << " -> " << method_ << " https://" << host_ << path_);
    relay();
}

bool Connection::read_connect_request() {
    std::string request_line;
    if (!read_line(client_fd_, request_line, 4096)) {
        LOG("Failed to read CONNECT line from " << client_ip_);
        return false;
    }
    std::istringstream iss(request_line);
    std::string method, host_port, version;
    if (!(iss >> method >> host_port >> version)) {
        LOG("Malformed request line from " << client_ip_ << ": " << request_line);
        return false;
    }
    if (method != "CONNECT") {
        LOG("Expected CONNECT, got " << method << " from " << client_ip_);
        constexpr char resp[] = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
        write_all(client_fd_, resp, sizeof(resp) - 1);
        return false;
    }
    const auto colon = host_port.rfind(':');
    if (colon == std::string::npos) {
        host_ = host_port; port_ = 443;
    } else {
        host_ = host_port.substr(0, colon);
        port_ = static_cast<uint16_t>(std::stoi(host_port.substr(colon + 1)));
    }
    std::string header_line;
    while (read_line(client_fd_, header_line, 4096))
        if (header_line.empty()) break;
    return true;
}

bool Connection::send_connect_ok() {
    constexpr char resp[] = "HTTP/1.1 200 Connection established\r\n\r\n";
    return write_all(client_fd_, resp, sizeof(resp) - 1);
}

bool Connection::ssl_handshake_client() {
    client_ssl_ = SSL_new(ssl_ctx_.get_server_ctx(host_));
    SSL_set_fd(client_ssl_, client_fd_);
    if (SSL_accept(client_ssl_) <= 0) {
        SSL_free(client_ssl_); client_ssl_ = nullptr;
        return false;
    }
    return true;
}

bool Connection::connect_upstream() {
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* raw = nullptr;
    if (getaddrinfo(host_.c_str(), std::to_string(port_).c_str(), &hints, &raw) != 0 || !raw) {
        LOG("DNS resolution failed for " << host_);
        return false;
    }
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> res(raw, freeaddrinfo);

    upstream_fd_ = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (::connect(upstream_fd_, res->ai_addr, res->ai_addrlen) != 0) {
        LOG("connect() failed to " << host_ << ":" << port_);
        return false;
    }

    upstream_ssl_ = SSL_new(ssl_ctx_.get_client_ctx());
    SSL_set_fd(upstream_ssl_, upstream_fd_);
    SSL_set_tlsext_host_name(upstream_ssl_, host_.c_str());
    if (SSL_connect(upstream_ssl_) <= 0) {
        SSL_free(upstream_ssl_); upstream_ssl_ = nullptr;
        return false;
    }
    return true;
}

bool Connection::read_http_request() {
    std::string line, version;
    if (!ssl_read_line(client_ssl_, line) ||
        !(std::istringstream(line) >> method_ >> path_ >> version)) {
        LOG("Malformed HTTP request from " << client_ip_);
        return false;
    }
    req_buf_ = line + "\r\n";
    while (ssl_read_line(client_ssl_, line) && !line.empty())
        req_buf_ += line + "\r\n";
    req_buf_ += "\r\n";
    return true;
}

void Connection::relay() {
    ssl_write_all(upstream_ssl_, req_buf_.c_str(), req_buf_.size());
    uint64_t bytes = ssl_relay(client_ssl_, upstream_ssl_) + req_buf_.size();
    stats_.record_request(host_, bytes, false);
}

void Connection::send_error(int status_code, const char* status_text, const char* body) {
    const std::string b = body;
    const std::string resp =
        "HTTP/1.1 " + std::to_string(status_code) + " " + status_text +
        "\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(b.size()) +
        "\r\nConnection: close\r\n\r\n" + b;
    if (client_ssl_) ssl_write_all(client_ssl_, resp.c_str(), resp.size());
    else             write_all(client_fd_, resp.c_str(), resp.size());
}

bool Connection::read_line(int fd, std::string& out, size_t max_len) {
    out.clear();
    char ch;
    while (out.size() < max_len) {
        ssize_t n = ::recv(fd, &ch, 1, 0);
        if (n <= 0) return !out.empty();
        if (ch == '\n') {
            if (!out.empty() && out.back() == '\r') out.pop_back();
            return true;
        }
        out += ch;
    }
    return false;
}

bool Connection::write_all(int fd, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool Connection::ssl_write_all(SSL* ssl, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, buf + sent, static_cast<int>(len - sent));
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

uint64_t Connection::ssl_relay(SSL* client_ssl, SSL* upstream_ssl) {
    const int client_fd   = SSL_get_fd(client_ssl);
    const int upstream_fd = SSL_get_fd(upstream_ssl);
    constexpr size_t BUF_SIZE = 16 * 1024;
    std::vector<char> buf(BUF_SIZE);
    uint64_t total_bytes = 0;
    bool client_eof = false, upstream_eof = false;

    while (!client_eof || !upstream_eof) {
        struct pollfd fds[2];
        int nfds = 0;
        if (!client_eof)   fds[nfds++] = {client_fd,   POLLIN, 0};
        if (!upstream_eof) fds[nfds++] = {upstream_fd, POLLIN, 0};

        if (SSL_pending(client_ssl) == 0 && SSL_pending(upstream_ssl) == 0) {
            int ready = ::poll(fds, nfds, 30000);
            if (ready <= 0) break;
        }

        auto fd_ready = [&](int fd) {
            for (int i = 0; i < nfds; ++i)
                if (fds[i].fd == fd && (fds[i].revents & POLLIN)) return true;
            return false;
        };

        if (SSL_pending(client_ssl) > 0 || (!client_eof && fd_ready(client_fd))) {
            int n = SSL_read(client_ssl, buf.data(), static_cast<int>(BUF_SIZE));
            if (n > 0) {
                total_bytes += static_cast<uint64_t>(n);
                if (!ssl_write_all(upstream_ssl, buf.data(), static_cast<size_t>(n))) break;
            } else { client_eof = true; }
        }

        if (SSL_pending(upstream_ssl) > 0 || (!upstream_eof && fd_ready(upstream_fd))) {
            int n = SSL_read(upstream_ssl, buf.data(), static_cast<int>(BUF_SIZE));
            if (n > 0) {
                total_bytes += static_cast<uint64_t>(n);
                if (!ssl_write_all(client_ssl, buf.data(), static_cast<size_t>(n))) break;
            } else { upstream_eof = true; }
        }
    }
    return total_bytes;
}
