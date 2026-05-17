#pragma once

#include <atomic>
#include <cstdint>
#include <shared_mutex>
#include <string>
#include <unordered_map>

struct DomainStats {
    std::atomic<uint64_t> requests{0};
    std::atomic<uint64_t> bytes{0};
    std::atomic<uint64_t> blocked{0};
};

class Stats {
public:
    void record_request(const std::string& domain,
                        uint64_t           bytes,
                        bool               blocked);
    std::string serve_stats_page() const;

    std::atomic<uint64_t> total_requests{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> total_blocked{0};
    std::atomic<uint64_t> active_connections{0};
private:
    DomainStats& get_domain(const std::string& domain);

    mutable std::shared_mutex                    domain_mutex_;
    std::unordered_map<std::string, DomainStats> domain_stats_;
};

// -----------------------------------------------------------------------------

#include <ctime>
#include <sstream>

DomainStats& Stats::get_domain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    return domain_stats_[domain];
}

void Stats::record_request(const std::string& domain,
                            uint64_t           bytes,
                            bool               is_blocked) {
    ++total_requests;
    total_bytes += bytes;
    if (is_blocked) ++total_blocked;

    DomainStats& ds = get_domain(domain);
    ++ds.requests;
    ds.bytes += bytes;
    if (is_blocked) ++ds.blocked;
}

std::string Stats::serve_stats_page() const {
    char time_buf[32];
    std::time_t now = std::time(nullptr);
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));

    std::ostringstream oss;
    oss << "{\n"
        << "  \"timestamp\": \""         << time_buf                   << "\",\n"
        << "  \"global\": {\n"
        << "    \"total_requests\": "     << total_requests.load()      << ",\n"
        << "    \"total_bytes\": "        << total_bytes.load()         << ",\n"
        << "    \"total_blocked\": "      << total_blocked.load()       << ",\n"
        << "    \"active_connections\": " << active_connections.load()  << "\n"
        << "  },\n"
        << "  \"domains\": {\n";

    {
        std::shared_lock<std::shared_mutex> rlock(domain_mutex_);
        bool first = true;
        for (const auto& [domain, ds] : domain_stats_) {
            if (!first) oss << ",\n";
            first = false;
            oss << "    \"" << domain << "\": {\"requests\": " << ds.requests.load()
                << ", \"bytes\": " << ds.bytes.load()
                << ", \"blocked\": " << ds.blocked.load() << "}";
        }
    }

    oss << "\n  }\n}\n";
    return oss.str();
}
