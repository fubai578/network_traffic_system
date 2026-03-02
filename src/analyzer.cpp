#include "../include/analyzer.h"
#include "../include/union_find.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <queue>
#include <vector>
#include <limits>
#include <sstream>
#include <unordered_set>
#include <set>

//将IP字符串转为32位无符号整数，便于范围比较
unsigned int Analyzer::ip_to_uint(const std::string& ip) {
    unsigned int result = 0;
    int octet = 0, shift = 24;
    for (char c : ip) {
        if (c == '.') {
            result |= ((unsigned int)octet << shift);
            shift -= 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= (unsigned int)octet; //最后一段
    return result;
}

//将路径（节点ID列表）格式化为可读字符串
std::string Analyzer::format_path(const std::vector<int>& path) const {
    if (path.empty()) return "(no path)";
    std::ostringstream oss;
    for (size_t i = 0; i < path.size(); i++) {
        if (i > 0) oss << " -> ";
        oss << graph_.ip_of(path[i]);
    }
    return oss.str();
}

//计算路径的总拥塞度
double Analyzer::path_congestion(const std::vector<int>& path) const {
    if (path.size() < 2) return 0.0;
    double total = 0.0;
    for (size_t i = 0; i + 1 < path.size(); i++) {
        //在出边中寻找(path[i] -> path[i+1])
        for (const auto* e : graph_.out_edges(path[i])) {
            if (e->dst_id == path[i + 1]) {
                total += e->congestion();
                break;
            }
        }
    }
    return total;
}

//对所有节点按总流量（出+入）降序排序并输出
void Analyzer::sort_nodes_by_traffic(int top_n) const {
    int n = graph_.node_count();
    std::vector<std::pair<long long, int>> ranked; //(total_bytes, node_id)
    ranked.reserve(n);

    for (int i = 0; i < n; i++) {
        ranked.emplace_back(graph_.node_info(i).total_bytes(), i);
    }
    std::sort(ranked.begin(), ranked.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    int limit = (top_n > 0) ? std::min(top_n, (int)ranked.size())
                             : (int)ranked.size();

    std::cout << "\n======== Node traffic ranking (top " << limit << ") ========\n";
    std::cout << std::left
              << std::setw(5)  << "Rank"
              << std::setw(18) << "IP"
              << std::setw(15) << "TotalBytes"
              << std::setw(15) << "OutBytes"
              << std::setw(15) << "InBytes" << "\n";
    std::cout << std::string(68, '-') << "\n";

    for (int r = 0; r < limit; r++) {
        const auto& ni = graph_.node_info(ranked[r].second);
        std::cout << std::left
                  << std::setw(5)  << (r + 1)
                  << std::setw(18) << ni.ip
                  << std::setw(15) << ni.total_bytes()
                  << std::setw(15) << ni.out_bytes
                  << std::setw(15) << ni.in_bytes << "\n";
    }
}

//筛选含HTTPS连接的节点并按流量排序（HTTPS=TCP+443端口）
void Analyzer::sort_https_nodes(int top_n) const {
    std::unordered_set<int> https_nodes;

    for (const auto& e : graph_.edges()) {
        //检查：该边是否有TCP(proto=6)的会话 且 目的端口=443
        auto it = e.proto_stats.find(6);
        if (it != e.proto_stats.end() && e.dst_port == 443) {
            https_nodes.insert(e.src_id);
            https_nodes.insert(e.dst_id);
        }
    }

    //按总流量排序
    std::vector<std::pair<long long, int>> ranked;
    for (int id : https_nodes) {
        ranked.emplace_back(graph_.node_info(id).total_bytes(), id);
    }
    std::sort(ranked.begin(), ranked.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    int limit = (top_n > 0) ? std::min(top_n, (int)ranked.size())
                             : (int)ranked.size();

    std::cout << "\n==== HTTPS nodes (total " << ranked.size()
              << ", show top " << limit << ") ====\n";
    std::cout << std::left
              << std::setw(5)  << "Rank"
              << std::setw(18) << "IP"
              << std::setw(15) << "TotalBytes"
              << std::setw(15) << "OutBytes"
              << std::setw(15) << "InBytes" << "\n";
    std::cout << std::string(68, '-') << "\n";

    for (int r = 0; r < limit; r++) {
        const auto& ni = graph_.node_info(ranked[r].second);
        std::cout << std::left
                  << std::setw(5)  << (r + 1)
                  << std::setw(18) << ni.ip
                  << std::setw(15) << ni.total_bytes()
                  << std::setw(15) << ni.out_bytes
                  << std::setw(15) << ni.in_bytes << "\n";
    }
}

//筛选单向流量占比>threshold的节点并排序
void Analyzer::sort_unidirectional_nodes(double threshold, int top_n) const {
    int n = graph_.node_count();
    std::vector<std::pair<long long, int>> ranked;

    for (int i = 0; i < n; i++) {
        const auto& ni = graph_.node_info(i);
        if (ni.total_bytes() == 0) continue;
        if (ni.out_ratio() > threshold) {
            ranked.emplace_back(ni.total_bytes(), i);
        }
    }
    std::sort(ranked.begin(), ranked.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    int limit = (top_n > 0) ? std::min(top_n, (int)ranked.size())
                             : (int)ranked.size();

    std::cout << "\n==== Unidirectional (outgoing >" << (int)(threshold * 100)
              << "%) nodes (total " << ranked.size()
              << ", show top " << limit << ") ====\n";
    std::cout << "(These nodes may indicate port scanning or other suspicious behavior)\n";
    std::cout << std::left
              << std::setw(5)  << "Rank"
              << std::setw(18) << "IP"
              << std::setw(15) << "TotalBytes"
              << std::setw(12) << "OutBytes"
              << std::setw(12) << "OutRatio%" << "\n";
    std::cout << std::string(62, '-') << "\n";

    for (int r = 0; r < limit; r++) {
        const auto& ni = graph_.node_info(ranked[r].second);
        std::cout << std::left
                  << std::setw(5)  << (r + 1)
                  << std::setw(18) << ni.ip
                  << std::setw(15) << ni.total_bytes()
                  << std::setw(12) << ni.out_bytes
                  << std::fixed << std::setprecision(1)
                  << (ni.out_ratio() * 100) << "%\n";
    }
}

//Dijkstra算法：寻找拥塞最小路径（边权=拥塞度=total_bytes/total_duration）
void Analyzer::find_min_congestion_path(const std::string& src_ip,
                                        const std::string& dst_ip) const {
    int src = graph_.id_of(src_ip);
    int dst = graph_.id_of(dst_ip);
    if (src < 0 || dst < 0) {
        std::cout << "[Path search] Node not found: "
                  << (src < 0 ? src_ip : "") << " "
                  << (dst < 0 ? dst_ip : "") << "\n";
        return;
    }
    if (src == dst) {
        std::cout << "[Path search] Source and destination are the same\n";
        return;
    }

    int n = graph_.node_count();
    const double INF = std::numeric_limits<double>::max();
    std::vector<double> dist(n, INF);
    std::vector<int>    prev(n, -1);
    //(distance, node_id)
    using pdi = std::pair<double, int>;
    std::priority_queue<pdi, std::vector<pdi>, std::greater<pdi>> pq;

    dist[src] = 0.0;
    pq.push({0.0, src});

    while (!pq.empty()) {
        auto [d, u] = pq.top(); pq.pop();
        if (d > dist[u]) continue;
        if (u == dst) break;

        for (const auto* e : graph_.out_edges(u)) {
            double w = e->congestion();
            if (dist[u] + w < dist[e->dst_id]) {
                dist[e->dst_id] = dist[u] + w;
                prev[e->dst_id] = u;
                pq.push({dist[e->dst_id], e->dst_id});
            }
        }
    }

    //回溯路径
    if (dist[dst] >= INF) {
        std::cout << "[Min-congestion path] " << src_ip << " -> " << dst_ip
                  << ": unreachable\n";
        return;
    }
    std::vector<int> path;
    for (int v = dst; v != -1; v = prev[v]) path.push_back(v);
    std::reverse(path.begin(), path.end());

    std::cout << "\n[Min-congestion path] " << src_ip << " -> " << dst_ip << "\n";
    std::cout << "  Path: " << format_path(path) << "\n";
    std::cout << "  Hops: " << (path.size() - 1) << "\n";
    std::cout << "  Total congestion: " << std::fixed << std::setprecision(2)
              << dist[dst] << " bytes/s\n";
}

//BFS算法：寻找跳数最小路径（无权图BFS）
void Analyzer::find_min_hop_path(const std::string& src_ip,
                                 const std::string& dst_ip) const {
    int src = graph_.id_of(src_ip);
    int dst = graph_.id_of(dst_ip);
    if (src < 0 || dst < 0) {
        std::cout << "[Path search] Node not found\n";
        return;
    }
    if (src == dst) {
        std::cout << "[Path search] Source and destination are the same\n";
        return;
    }

    int n = graph_.node_count();
    std::vector<int> prev(n, -1);
    std::vector<bool> visited(n, false);
    std::queue<int> bfsq;

    visited[src] = true;
    bfsq.push(src);

    while (!bfsq.empty()) {
        int u = bfsq.front(); bfsq.pop();
        if (u == dst) break;
        for (const auto* e : graph_.out_edges(u)) {
            if (!visited[e->dst_id]) {
                visited[e->dst_id] = true;
                prev[e->dst_id]    = u;
                bfsq.push(e->dst_id);
            }
        }
    }

    if (!visited[dst]) {
        std::cout << "[Min-hop path] " << src_ip << " -> " << dst_ip
                  << ": unreachable\n";
        return;
    }
    std::vector<int> path;
    for (int v = dst; v != -1; v = prev[v]) path.push_back(v);
    std::reverse(path.begin(), path.end());

    std::cout << "\n[Min-hop path] " << src_ip << " -> " << dst_ip << "\n";
    std::cout << "  Path: " << format_path(path) << "\n";
    std::cout << "  Hops: " << (path.size() - 1) << "\n";
    std::cout << "  Path total congestion: " << std::fixed << std::setprecision(2)
              << path_congestion(path) << " bytes/s\n";
}

//对比拥塞最小路径和跳数最小路径
void Analyzer::compare_paths(const std::string& src_ip,
                              const std::string& dst_ip) const {
    std::cout << "\n========== Path comparison: " << src_ip << " -> " << dst_ip
              << " ==========\n";

    int src = graph_.id_of(src_ip);
    int dst = graph_.id_of(dst_ip);
    if (src < 0 || dst < 0) {
        std::cout << "  Node not found!\n";
        return;
    }

    int n = graph_.node_count();
    const double INF = std::numeric_limits<double>::max();

    //--- min-congestion path (Dijkstra) ---
    std::vector<double> dist_c(n, INF);
    std::vector<int>    prev_c(n, -1);
    using pdi = std::pair<double, int>;
    std::priority_queue<pdi, std::vector<pdi>, std::greater<pdi>> pq;
    dist_c[src] = 0.0;
    pq.push({0.0, src});
    while (!pq.empty()) {
        auto [d, u] = pq.top(); pq.pop();
        if (d > dist_c[u]) continue;
        for (const auto* e : graph_.out_edges(u)) {
            double w = e->congestion();
            if (dist_c[u] + w < dist_c[e->dst_id]) {
                dist_c[e->dst_id] = dist_c[u] + w;
                prev_c[e->dst_id] = u;
                pq.push({dist_c[e->dst_id], e->dst_id});
            }
        }
    }
    std::vector<int> cpath;
    if (dist_c[dst] < INF) {
        for (int v = dst; v != -1; v = prev_c[v]) cpath.push_back(v);
        std::reverse(cpath.begin(), cpath.end());
    }

    //--- min-hop path (BFS) ---
    std::vector<int> prev_b(n, -1);
    std::vector<bool> vis(n, false);
    std::queue<int> bq;
    vis[src] = true; bq.push(src);
    while (!bq.empty()) {
        int u = bq.front(); bq.pop();
        if (u == dst) break;
        for (const auto* e : graph_.out_edges(u)) {
            if (!vis[e->dst_id]) {
                vis[e->dst_id] = true;
                prev_b[e->dst_id] = u;
                bq.push(e->dst_id);
            }
        }
    }
    std::vector<int> bpath;
    if (vis[dst]) {
        for (int v = dst; v != -1; v = prev_b[v]) bpath.push_back(v);
        std::reverse(bpath.begin(), bpath.end());
    }

    //输出对比结果
    std::cout << "\n  [Plan A - Min-congestion path (Dijkstra)]\n";
    if (cpath.empty()) {
        std::cout << "    Unreachable\n";
    } else {
        std::cout << "    Path:     " << format_path(cpath) << "\n";
        std::cout << "    Hops:     " << (cpath.size() - 1) << "\n";
        std::cout << "    Congestion: " << std::fixed << std::setprecision(2)
                  << dist_c[dst] << " bytes/s\n";
    }

    std::cout << "\n  [Plan B - Min-hop path (BFS)]\n";
    if (bpath.empty()) {
        std::cout << "    Unreachable\n";
    } else {
        std::cout << "    Path:     " << format_path(bpath) << "\n";
        std::cout << "    Hops:     " << (bpath.size() - 1) << "\n";
        std::cout << "    Congestion: " << std::fixed << std::setprecision(2)
                  << path_congestion(bpath) << " bytes/s\n";
    }

    //判断两条路径是否相同
    if (!cpath.empty() && !bpath.empty()) {
        if (cpath == bpath) {
            std::cout << "\n  Two paths are the same; in this graph the shortest path is also optimal.\n";
        } else {
            std::cout << "\n  Two paths are different:\n"
                      << "    Plan A is better in congestion control (lower total congestion).\n"
                      << "    Plan B is better in hop count (fewer nodes).\n"
                      << "    Suggestion: when the network is congested, prefer Plan A; "
                         "otherwise choose Plan B to reduce latency.\n";
        }
    }
    std::cout << std::string(60, '=') << "\n";
}

//检测图中的星型拓扑结构（中心节点≥20个叶节点且叶节点仅连中心）
void Analyzer::detect_star_topology() const {
    const int MIN_LEAVES = 20;
    bool found_any = false;

    std::cout << "\n======== Star topology detection ========\n";
    std::cout << "Definition: center node connected with >=20 leaf nodes\n"
                 "that only connect to this center.\n\n";

    int n = graph_.node_count();
    for (int center = 0; center < n; center++) {
        auto out_e = graph_.out_edges(center);
        if ((int)out_e.size() < MIN_LEAVES) continue;

        std::vector<int> leaves;
        for (const auto* e : out_e) {
            int leaf = e->dst_id;
            if (leaf == center) continue;
            //叶节点的出度 + 入度 之和应恰好表明只与中心节点相连
            auto leaf_out = graph_.out_edges(leaf);
            auto leaf_in  = graph_.in_edges(leaf);
            //检查叶节点：其所有邻居均为center
            bool is_pure_leaf = true;
            for (const auto* le : leaf_out) {
                if (le->dst_id != center) { is_pure_leaf = false; break; }
            }
            if (!is_pure_leaf) continue;
            for (const auto* le : leaf_in) {
                if (le->src_id != center) { is_pure_leaf = false; break; }
            }
            if (is_pure_leaf) leaves.push_back(leaf);
        }

        if ((int)leaves.size() >= MIN_LEAVES) {
            found_any = true;
            std::cout << "Center node: " << graph_.ip_of(center) << "\n";
            std::cout << "Leaf count: " << leaves.size() << "\n";
            std::cout << "Connected nodes: ";
            for (size_t i = 0; i < leaves.size(); i++) {
                if (i > 0) std::cout << ", ";
                std::cout << graph_.ip_of(leaves[i]);
            }
            std::cout << "\n" << std::string(50, '-') << "\n";
        }
    }

    if (!found_any) {
        std::cout << "  No star topology found (leaf nodes must be >= 20).\n";
    }
}

//根据安全规则检查违规会话（src_ip禁止/允许与指定IP范围通信）
void Analyzer::check_security_rule(const SecurityRule& rule) const {
    std::cout << "\n======== Security rule check ========\n";
    std::string action_str = (rule.action == RuleAction::DENY) ? "DENY" : "ALLOW";
    std::cout << "Rule: IP " << rule.src_ip << " " << action_str
              << " sessions with IPs in range [" << rule.range_start << " ~ "
              << rule.range_end << "]\n\n";

    unsigned int range_lo = ip_to_uint(rule.range_start);
    unsigned int range_hi = ip_to_uint(rule.range_end);
    if (range_lo > range_hi) std::swap(range_lo, range_hi);

    int src_node = graph_.id_of(rule.src_ip);
    if (src_node < 0) {
        std::cout << "  Source IP in rule does not exist in the graph.\n";
        return;
    }

    int violation_count = 0;
    std::cout << std::left
              << std::setw(18) << "SrcIP"
              << std::setw(18) << "DstIP"
              << std::setw(10) << "Proto"
              << std::setw(12) << "Bytes"
              << "Reason\n";
    std::cout << std::string(70, '-') << "\n";

    //检查该节点的出边（发出方向）
    for (const auto* e : graph_.out_edges(src_node)) {
        unsigned int dst_ip_int = ip_to_uint(graph_.ip_of(e->dst_id));
        bool in_range = (dst_ip_int >= range_lo && dst_ip_int <= range_hi);
        bool is_violation = (rule.action == RuleAction::DENY && in_range) ||
                            (rule.action == RuleAction::ALLOW && !in_range);
        if (is_violation) {
            violation_count++;
            std::string reason = (rule.action == RuleAction::DENY)
                ? "Send to IP in denied range"
                : "Send to IP outside allowed range";
            //获取主协议名称
            std::string proto_name = "Unknown";
            if (!e->proto_stats.empty()) {
                int main_proto = e->proto_stats.begin()->first;
                auto it = PROTOCOL_NAMES.find(main_proto);
                proto_name = (it != PROTOCOL_NAMES.end()) ? it->second
                             : std::to_string(main_proto);
            }
            std::cout << std::left
                      << std::setw(18) << graph_.ip_of(e->src_id)
                      << std::setw(18) << graph_.ip_of(e->dst_id)
                      << std::setw(10) << proto_name
                      << std::setw(12) << e->total_bytes
                      << reason << "\n";
        }
    }

    //检查该节点的入边（接收方向）
    for (const auto* e : graph_.in_edges(src_node)) {
        unsigned int src_ip_int = ip_to_uint(graph_.ip_of(e->src_id));
        bool in_range = (src_ip_int >= range_lo && src_ip_int <= range_hi);
        bool is_violation = (rule.action == RuleAction::DENY && in_range) ||
                            (rule.action == RuleAction::ALLOW && !in_range);
        if (is_violation) {
            violation_count++;
            std::string reason = (rule.action == RuleAction::DENY)
                ? "Receive from IP in denied range"
                : "Receive from IP outside allowed range";
            std::string proto_name = "Unknown";
            if (!e->proto_stats.empty()) {
                int main_proto = e->proto_stats.begin()->first;
                auto it = PROTOCOL_NAMES.find(main_proto);
                proto_name = (it != PROTOCOL_NAMES.end()) ? it->second
                             : std::to_string(main_proto);
            }
            std::cout << std::left
                      << std::setw(18) << graph_.ip_of(e->src_id)
                      << std::setw(18) << graph_.ip_of(e->dst_id)
                      << std::setw(10) << proto_name
                      << std::setw(12) << e->total_bytes
                      << reason << "\n";
        }
    }

    if (violation_count == 0) {
        std::cout << "  No violation sessions found.\n";
    } else {
        std::cout << "\nTotal " << violation_count << " violation sessions found.\n";
    }
}