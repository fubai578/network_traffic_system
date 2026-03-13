#include "../include/analyzer.h"
#include "../include/union_find.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <queue>
#include <limits>
#include <sstream>
#include <unordered_set>

//IP字符串转32位整数
unsigned int Analyzer::ip_to_uint(const std::string& ip) {
    unsigned int result = 0;
    int octet = 0, shift = 24;
    for (char c : ip) {
        if (c == '.') { result |= (unsigned int)octet << shift; shift -= 8; octet = 0; }
        else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
    }
    return result | (unsigned int)octet;
}

//节点ID列表 → "IP1 -> IP2 -> ..."
std::string Analyzer::format_path(const std::vector<int>& path) const {
    if (path.empty()) return "(no path)";
    std::ostringstream oss;
    for (size_t i = 0; i < path.size(); i++) {
        if (i) oss << " -> ";
        oss << graph_.ip_of(path[i]);
    }
    return oss.str();
}

//路径总拥塞度（各边 congestion() 之和）
double Analyzer::path_congestion(const std::vector<int>& path) const {
    double total = 0.0;
    for (size_t i = 0; i + 1 < path.size(); i++)
        for (const auto* e : graph_.out_edges(path[i]))
            if (e->dst_id == path[i + 1]) { total += e->congestion(); break; }
    return total;
}

//打印节点排名表（带表头，统一列宽）
// mode 0: Rank/IP/Total/Out/In；mode 1: Rank/IP/Total/Out/OutRatio%
static void print_node_table(const Graph& g,
                              const std::vector<std::pair<long long,int>>& ranked,
                              int limit, int mode) {
    std::cout << std::left;
    if (mode == 0) {
        std::cout << std::setw(5) <<"Rank" <<std::setw(18)<<"IP"
                  <<std::setw(15)<<"TotalBytes"<<std::setw(15)<<"OutBytes"
                  <<std::setw(15)<<"InBytes\n" <<std::string(68,'-')<<"\n";
        for (int r = 0; r < limit; r++) {
            const auto& ni = g.node_info(ranked[r].second);
            std::cout <<std::setw(5)<<(r+1)<<std::setw(18)<<ni.ip
                      <<std::setw(15)<<ni.total_bytes()<<std::setw(15)<<ni.out_bytes
                      <<std::setw(15)<<ni.in_bytes<<"\n";
        }
    } else {
        std::cout << std::setw(5)<<"Rank"<<std::setw(18)<<"IP"
                  <<std::setw(15)<<"TotalBytes"<<std::setw(12)<<"OutBytes"
                  <<"OutRatio%\n"<<std::string(62,'-')<<"\n";
        for (int r = 0; r < limit; r++) {
            const auto& ni = g.node_info(ranked[r].second);
            std::cout <<std::setw(5)<<(r+1)<<std::setw(18)<<ni.ip
                      <<std::setw(15)<<ni.total_bytes()<<std::setw(12)<<ni.out_bytes
                      <<std::fixed<<std::setprecision(1)<<(ni.out_ratio()*100)<<"%\n";
        }
    }
}

//Dijkstra（拥塞权重），返回 prev 数组和 dist[dst]
static std::pair<std::vector<int>, double>
run_dijkstra(const Graph& g, int src, int dst) {
    const double INF = std::numeric_limits<double>::max();
    int n = g.node_count();
    std::vector<double> dist(n, INF);
    std::vector<int> prev(n, -1);
    using pdi = std::pair<double,int>;
    std::priority_queue<pdi, std::vector<pdi>, std::greater<pdi>> pq;
    dist[src] = 0.0; pq.push({0.0, src});
    while (!pq.empty()) {
        auto [d, u] = pq.top(); pq.pop();
        if (d > dist[u] || u == dst) continue;
        for (const auto* e : g.out_edges(u)) {
            double nd = dist[u] + e->congestion();
            if (nd < dist[e->dst_id]) { dist[e->dst_id] = nd; prev[e->dst_id] = u; pq.push({nd, e->dst_id}); }
        }
    }
    return {prev, dist[dst]};
}

//私有辅助：BFS（无权），返回 prev 数组和是否可达
static std::pair<std::vector<int>, bool>
run_bfs(const Graph& g, int src, int dst) {
    int n = g.node_count();
    std::vector<int> prev(n, -1);
    std::vector<bool> vis(n, false);
    std::queue<int> q;
    vis[src] = true; q.push(src);
    while (!q.empty()) {
        int u = q.front(); q.pop();
        if (u == dst) break;
        for (const auto* e : g.out_edges(u))
            if (!vis[e->dst_id]) { vis[e->dst_id] = true; prev[e->dst_id] = u; q.push(e->dst_id); }
    }
    return {prev, vis[dst]};
}

//从prev数组回溯路径
static std::vector<int> backtrack(const std::vector<int>& prev, int dst) {
    std::vector<int> path;
    for (int v = dst; v != -1; v = prev[v]) path.push_back(v);
    std::reverse(path.begin(), path.end());
    return path;
}

//公有接口实现

//对所有节点按总流量（出+入）降序排序并输出
void Analyzer::sort_nodes_by_traffic(int top_n) const {
    int n = graph_.node_count();
    std::vector<std::pair<long long,int>> ranked;
    ranked.reserve(n);
    for (int i = 0; i < n; i++) ranked.emplace_back(graph_.node_info(i).total_bytes(), i);
    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b){ return a.first > b.first; });
    int limit = top_n > 0 ? std::min(top_n,(int)ranked.size()) : (int)ranked.size();
    std::cout << "\n======== Node traffic ranking (top " << limit << ") ========\n";
    print_node_table(graph_, ranked, limit, 0);
}

// 筛选含HTTPS连接的节点（TCP+443）并按流量排序
void Analyzer::sort_https_nodes(int top_n) const {
    std::unordered_set<int> https_set;
    for (const auto& e : graph_.edges())
        if (e.proto_stats.count(6) && e.dst_port == 443)
            { https_set.insert(e.src_id); https_set.insert(e.dst_id); }

    std::vector<std::pair<long long,int>> ranked;
    for (int id : https_set) ranked.emplace_back(graph_.node_info(id).total_bytes(), id);
    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b){ return a.first > b.first; });
    int limit = top_n > 0 ? std::min(top_n,(int)ranked.size()) : (int)ranked.size();
    std::cout << "\n==== HTTPS nodes (total " << ranked.size() << ", show top " << limit << ") ====\n";
    print_node_table(graph_, ranked, limit, 0);
}

// 筛选单向流量占比>threshold的节点并排序
void Analyzer::sort_unidirectional_nodes(double threshold, int top_n) const {
    std::vector<std::pair<long long,int>> ranked;
    for (int i = 0; i < graph_.node_count(); i++) {
        const auto& ni = graph_.node_info(i);
        if (ni.total_bytes() > 0 && ni.out_ratio() > threshold)
            ranked.emplace_back(ni.total_bytes(), i);
    }
    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b){ return a.first > b.first; });
    int limit = top_n > 0 ? std::min(top_n,(int)ranked.size()) : (int)ranked.size();
    std::cout << "\n==== Unidirectional (outgoing >" << (int)(threshold*100)
              << "%) nodes (total " << ranked.size() << ", show top " << limit << ") ====\n"
              << "(These nodes may indicate port scanning or other suspicious behavior)\n";
    print_node_table(graph_, ranked, limit, 1);
}

//Dijkstra：寻找拥塞最小路径
void Analyzer::find_min_congestion_path(const std::string& src_ip,
                                        const std::string& dst_ip) const {
    int src = graph_.id_of(src_ip), dst = graph_.id_of(dst_ip);
    if (src < 0 || dst < 0) { std::cout << "[Path] Node not found\n"; return; }
    if (src == dst)          { std::cout << "[Path] Same node\n"; return; }
    auto [prev, cost] = run_dijkstra(graph_, src, dst);
    if (cost >= std::numeric_limits<double>::max()) { std::cout << "[Min-congestion] Unreachable\n"; return; }
    auto path = backtrack(prev, dst);
    std::cout << "\n[Min-congestion path] " << format_path(path)
              << "\n  Hops: " << path.size()-1
              << "  Congestion: " << std::fixed << std::setprecision(2) << cost << " bytes/s\n";
}

//BFS：寻找跳数最小路径
void Analyzer::find_min_hop_path(const std::string& src_ip,
                                 const std::string& dst_ip) const {
    int src = graph_.id_of(src_ip), dst = graph_.id_of(dst_ip);
    if (src < 0 || dst < 0) { std::cout << "[Path] Node not found\n"; return; }
    if (src == dst)          { std::cout << "[Path] Same node\n"; return; }
    auto [prev, reachable] = run_bfs(graph_, src, dst);
    if (!reachable) { std::cout << "[Min-hop] Unreachable\n"; return; }
    auto path = backtrack(prev, dst);
    std::cout << "\n[Min-hop path] " << format_path(path)
              << "\n  Hops: " << path.size()-1
              << "  Congestion: " << std::fixed << std::setprecision(2)
              << path_congestion(path) << " bytes/s\n";
}

//对比两条路径（Dijkstra vs BFS）
void Analyzer::compare_paths(const std::string& src_ip,
                              const std::string& dst_ip) const {
    int src = graph_.id_of(src_ip), dst = graph_.id_of(dst_ip);
    std::cout << "\n========== Path comparison: " << src_ip << " -> " << dst_ip << " ==========\n";
    if (src < 0 || dst < 0) { std::cout << "  Node not found!\n"; return; }

    auto [prev_c, cost_c] = run_dijkstra(graph_, src, dst);
    auto [prev_b, reach_b] = run_bfs(graph_, src, dst);
    std::vector<int> cpath = (cost_c < std::numeric_limits<double>::max()) ? backtrack(prev_c, dst) : std::vector<int>{};
    std::vector<int> bpath = reach_b ? backtrack(prev_b, dst) : std::vector<int>{};

    std::cout << "\n  [Plan A - Min-congestion (Dijkstra)]\n";
    if (cpath.empty()) std::cout << "    Unreachable\n";
    else std::cout << "    Path: " << format_path(cpath) << "\n"
                   << "    Hops: " << cpath.size()-1 << "  Congestion: "
                   << std::fixed << std::setprecision(2) << cost_c << " bytes/s\n";

    std::cout << "\n  [Plan B - Min-hop (BFS)]\n";
    if (bpath.empty()) std::cout << "    Unreachable\n";
    else std::cout << "    Path: " << format_path(bpath) << "\n"
                   << "    Hops: " << bpath.size()-1 << "  Congestion: "
                   << std::fixed << std::setprecision(2) << path_congestion(bpath) << " bytes/s\n";

    if (!cpath.empty() && !bpath.empty()) {
        if (cpath == bpath)
            std::cout << "\n  Two paths are the same.\n";
        else
            std::cout << "\n  Paths differ: Plan A minimizes congestion; Plan B minimizes hops.\n";
    }
    std::cout << std::string(60,'=') << "\n";
}

//检测星型拓扑（中心节点拥有>=20个纯叶节点）
void Analyzer::detect_star_topology() const {
    std::cout << "\n======== Star topology detection ========\n"
                 "Definition: center connected to >=20 nodes (via out or in edges) that only connect to this center.\n\n";
    bool found = false;
    for (int center = 0; center < graph_.node_count(); center++) {
        // 收集中心节点所有邻居（出边目标 + 入边来源），去重
        std::unordered_set<int> neighbors;
        for (const auto* e : graph_.out_edges(center)) neighbors.insert(e->dst_id);
        for (const auto* e : graph_.in_edges(center))  neighbors.insert(e->src_id);
        neighbors.erase(center); // 排除自环

        if ((int)neighbors.size() < 20) continue;

        // 筛选纯叶节点：所有出边和入边都只与中心节点相连
        std::vector<int> leaves;
        for (int leaf : neighbors) {
            bool pure = true;
            for (const auto* le : graph_.out_edges(leaf)) if (le->dst_id != center) { pure = false; break; }
            if (pure) for (const auto* le : graph_.in_edges(leaf)) if (le->src_id != center) { pure = false; break; }
            if (pure) leaves.push_back(leaf);
        }
        if ((int)leaves.size() < 20) continue;
        found = true;
        std::cout << "Center: " << graph_.ip_of(center) << "  Leaves: " << leaves.size() << "\n";
        for (size_t i = 0; i < leaves.size(); i++) {
            if (i) std::cout << ", ";
            std::cout << graph_.ip_of(leaves[i]);
        }
        std::cout << "\n" << std::string(50,'-') << "\n";
    }
    if (!found) std::cout << "  No star topology found.\n";
}

//安全规则检查：打印违规会话（出边+入边合并处理）
void Analyzer::check_security_rule(const SecurityRule& rule) const {
    bool deny = (rule.action == RuleAction::DENY);
    std::cout << "\n======== Security rule check ========\n"
              << "Rule: " << rule.src_ip << (deny?" DENY":" ALLOW")
              << " sessions with [" << rule.range_start << " ~ " << rule.range_end << "]\n\n";

    unsigned int lo = ip_to_uint(rule.range_start), hi = ip_to_uint(rule.range_end);
    if (lo > hi) std::swap(lo, hi);
    int src_node = graph_.id_of(rule.src_ip);
    if (src_node < 0) { std::cout << "  Source IP not in graph.\n"; return; }

    // 获取协议名称的辅助 lambda
    auto proto_name = [](const Edge* e) -> std::string {
        if (e->proto_stats.empty()) return "Unknown";
        int p = e->proto_stats.begin()->first;
        auto it = PROTOCOL_NAMES.find(p);
        return it != PROTOCOL_NAMES.end() ? it->second : std::to_string(p);
    };

    std::cout << std::left <<std::setw(18)<<"SrcIP"<<std::setw(18)<<"DstIP"
              <<std::setw(10)<<"Proto"<<std::setw(12)<<"Bytes"<<"Reason\n"
              <<std::string(70,'-')<<"\n";
    int cnt = 0;

    // 出边和入边统一处理
    auto check = [&](const Edge* e, unsigned int peer_ip, const std::string& reason) {
        bool in_range = (peer_ip >= lo && peer_ip <= hi);
        if ((deny && in_range) || (!deny && !in_range)) {
            cnt++;
            std::cout <<std::left<<std::setw(18)<<graph_.ip_of(e->src_id)
                      <<std::setw(18)<<graph_.ip_of(e->dst_id)
                      <<std::setw(10)<<proto_name(e)<<std::setw(12)<<e->total_bytes<<reason<<"\n";
        }
    };

    for (const auto* e : graph_.out_edges(src_node))
        check(e, ip_to_uint(graph_.ip_of(e->dst_id)),
              deny ? "Send to IP in denied range" : "Send to IP outside allowed range");
    for (const auto* e : graph_.in_edges(src_node))
        check(e, ip_to_uint(graph_.ip_of(e->src_id)),
              deny ? "Receive from IP in denied range" : "Receive from IP outside allowed range");

    if (cnt == 0) std::cout << "  No violations found.\n";
    else std::cout << "\nTotal " << cnt << " violation(s) found.\n";
}