#include <windows.h>
#include "csv_reader.h"
#include "graph.h"
#include "analyzer.h"
#include "union_find.h"
#include "types.h"
#include <iostream>
#include <string>
#include <limits>
#include <fstream>
#include <unordered_set>

//数据未加载时打印提示，返回true表示应跳过本case
static bool need_load(bool loaded) {
    if (!loaded) std::cout << "Please load data first (option 1).\n";
    return !loaded;
}

//将query_ip所在连通子图导出为JSON，并发出SUBGRAPH_READY信号
static bool export_subgraph(const Graph& g, const std::string& query_ip) {
    if (g.id_of(query_ip) < 0) {
        std::cout << "[Error] IP not found: " << query_ip << "\n";
        return false;
    }

    //并查集定位连通分量
    UnionFind uf(g.node_count());
    for (const auto& e : g.edges()) uf.unite(e.src_id, e.dst_id);
    auto comp = uf.get_component(g.id_of(query_ip), g.node_count());
    std::unordered_set<int> comp_set(comp.begin(), comp.end());
    std::cout << "[Subgraph] Component size: " << comp.size() << " nodes\n";

    std::ofstream jf("subgraph_data.json");
    if (!jf) { std::cout << "[Error] Cannot write JSON.\n"; return false; }

    //节点只输出id和total_bytes
    jf << "{\"query_ip\":\"" << query_ip << "\",\"nodes\":[";
    for (size_t i = 0; i < comp.size(); i++) {
        const auto& ni = g.node_info(comp[i]);
        if (i) jf << ",";
        jf << "{\"id\":\"" << ni.ip << "\",\"total_bytes\":" << ni.total_bytes() << "}";
    }

    //边，输出source/target/bytes/sessions/protocol
    jf << "],\"edges\":[";
    bool first = true;
    for (const auto& e : g.edges()) {
        if (!comp_set.count(e.src_id) || !comp_set.count(e.dst_id)) continue;
        auto it = e.proto_stats.empty() ? PROTOCOL_NAMES.end()
                                        : PROTOCOL_NAMES.find(e.proto_stats.begin()->first);
        std::string proto = (it != PROTOCOL_NAMES.end()) ? it->second : "Unknown";
        if (!first) jf << ","; first = false;
        jf << "{\"source\":\"" << g.ip_of(e.src_id)
           << "\",\"target\":\"" << g.ip_of(e.dst_id)
           << "\",\"bytes\":"    << e.total_bytes
           << ",\"sessions\":"   << e.session_count
           << ",\"protocol\":\"" << proto << "\"}";
    }
    jf << "]}\n";

    //通知Python GUI子图已就绪
    std::cout << "SUBGRAPH_READY:" << query_ip << "\n";
    std::cout.flush();
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "\n  Network Traffic Analysis & Anomaly Detection\n\n";
    std::string csv_path = (argc > 1) ? argv[1] : "data/network_data.csv";
    std::vector<SessionRecord> records;
    Graph graph;
    bool loaded = false;

    int choice = -1;
    while (choice != 0) {
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        switch (choice) {

        case 1: {   //加载 CSV 并构建图
            std::cout << "CSV file path [default: " << csv_path << "]: ";
            std::cin.ignore();
            std::string input; std::getline(std::cin, input);
            if (!input.empty()) csv_path = input;
            records.clear();
            if (!CsvReader::load(csv_path, records) || records.empty()) {
                std::cout << "[Error] Failed to load data.\n"; break;
            }
            graph = Graph(); graph.build(records); loaded = true;
            std::cout << "Data loaded and graph built successfully!\n";
            break;
        }

        case 2: {   //展示子图
            if (need_load(loaded)) break;
            std::string qip; std::cout << "Enter IP: "; std::cin >> qip;
            export_subgraph(graph, qip);
            break;
        }

        case 3: {   //节点流量排序
            if (need_load(loaded)) break;
            int n; std::cout << "Show top N (0=all): "; std::cin >> n;
            Analyzer(graph).sort_nodes_by_traffic(n);
            break;
        }

        case 4: {   //HTTPS节点排序
            if (need_load(loaded)) break;
            int n; std::cout << "Show top N (0=all): "; std::cin >> n;
            Analyzer(graph).sort_https_nodes(n);
            break;
        }

        case 5: {   //单向流量节点排序
            if (need_load(loaded)) break;
            double thresh; std::cout << "Outgoing ratio threshold (default 0.8): "; std::cin >> thresh;
            if (thresh <= 0 || thresh > 1) thresh = 0.8;
            int n; std::cout << "Show top N (0=all): "; std::cin >> n;
            Analyzer(graph).sort_unidirectional_nodes(thresh, n);
            break;
        }

        case 6: {   //路径查找与对比
            if (need_load(loaded)) break;
            std::string src, dst;
            std::cout << "Enter source IP: ";      std::cin >> src;
            std::cout << "Enter destination IP: "; std::cin >> dst;
            Analyzer(graph).compare_paths(src, dst);
            break;
        }

        case 7: {   //星型拓扑检测
            if (need_load(loaded)) break;
            Analyzer(graph).detect_star_topology();
            break;
        }

        case 8: {   //安全规则检查
            if (need_load(loaded)) break;
            SecurityRule rule;
            std::cout << "Enter source IP (addr1): ";   std::cin >> rule.src_ip;
            std::cout << "Enter range start (addr2): "; std::cin >> rule.range_start;
            std::cout << "Enter range end   (addr3): "; std::cin >> rule.range_end;
            int act; std::cout << "Action (1=DENY / 0=ALLOW): "; std::cin >> act;
            rule.action = (act == 1) ? RuleAction::DENY : RuleAction::ALLOW;
            Analyzer(graph).check_security_rule(rule);
            break;
        }
        case 0: std::cout << "\nGoodbye!\n"; break;
        default: std::cout << "Invalid choice.\n";
        }
    }
    return 0;
}