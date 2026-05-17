#pragma once

#include <string>
#include <unordered_set>
#include <vector>

class Blocker {
public:
    Blocker() = default;
    bool load(const std::string& filepath);
    bool is_blocked(const std::string& host, const std::string& path) const;
private:
    std::unordered_set<std::string>                  blocked_domains_;
    std::vector<std::pair<std::string, std::string>> blocked_url_prefixes_;
};

// -----------------------------------------------------------------------------

#include <algorithm>
#include <fstream>
#include <iostream>

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string trim(const std::string& s) {
    const auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    const auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool Blocker::load(const std::string& filepath) {
    std::ifstream file(filepath);
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        line = to_lower(line);
        const auto slash_pos = line.find('/');
        if (slash_pos == std::string::npos) {
            blocked_domains_.insert(line);
        } else {
            std::string host   = line.substr(0, slash_pos);
            std::string prefix = line.substr(slash_pos);
            blocked_url_prefixes_.emplace_back(std::move(host), std::move(prefix));
        }
    }
    std::cerr << "[Blocker] Loaded " << blocked_domains_.size()
              << " domain(s) and " << blocked_url_prefixes_.size()
              << " URL prefix(es) from " << filepath << "\n";
    return true;
}

bool Blocker::is_blocked(const std::string& host, const std::string& path) const {
    const std::string lhost = to_lower(host);
    const std::string lpath = to_lower(path);
    if (blocked_domains_.count(lhost)) return true;
    for (const auto& [bhost, bprefix] : blocked_url_prefixes_) {
        if (lhost == bhost && lpath.rfind(bprefix, 0) == 0)
            return true;
    }
    return false;
}
