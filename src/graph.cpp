#include "../include/graph.h"
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>

//生成边的唯一键："srcID:dstID"
static std::string edge_key(int src, int dst) {
    return std::to_string(src) + ":" + std::to_string(dst);
}

//获取或分配IP对应的整数节点ID
int Graph::get_or_create_id(const std::string& ip) {
    auto it = ip_to_id_.find(ip);
    if (it != ip_to_id_.end()) return it->second;
    int new_id = (int)id_to_ip_.size();
    ip_to_id_[ip] = new_id;
    id_to_ip_.push_back(ip);
    return new_id;
}

//通过IP获取节点ID，不存在返回-1
int Graph::id_of(const std::string& ip) const {
    auto it = ip_to_id_.find(ip);
    return (it == ip_to_id_.end()) ? -1 : it->second;
}

//从原始会话记录构建图：分配节点ID→合并边→构建CSR→入边索引→统计节点流量
void Graph::build(const std::vector<SessionRecord>& records) {
    //收集并合并边
    std::unordered_map<std::string, Edge> raw_edges;

    for (const auto& rec : records) {
        int src_id = get_or_create_id(rec.src_ip);
        int dst_id = get_or_create_id(rec.dst_ip);

        std::string key = edge_key(src_id, dst_id);
        auto& e = raw_edges[key];
        if (e.session_count == 0) {
            e.src_id = src_id;
            e.dst_id = dst_id;
        }
        e.total_bytes    += rec.data_size;
        e.total_duration += rec.duration;
        e.session_count  += 1;
        e.src_port        = rec.src_port;
        e.dst_port        = rec.dst_port;

        //按协议统计
        auto& ps = e.proto_stats[rec.protocol];
        ps.total_bytes    += rec.data_size;
        ps.total_duration += rec.duration;
        ps.session_count  += 1;
    }

    //构建CSR、入边索引、节点统计
    build_csr(raw_edges);
    build_in_index();
    compute_node_infos();

    std::cout << "[图构建] 节点数: " << node_count()
              << "，边数（合并后）: " << edge_count() << std::endl;
}

//构建CSR邻接表：row_ptr[i]为节点i出边起始下标
void Graph::build_csr(std::unordered_map<std::string, Edge>& raw_edges) {
    int n = node_count();
    //收集所有边并按src_id排序
    std::vector<Edge> all_edges;
    all_edges.reserve(raw_edges.size());
    for (auto& kv : raw_edges) all_edges.push_back(kv.second);
    std::sort(all_edges.begin(), all_edges.end(),
              [](const Edge& a, const Edge& b) {
                  return a.src_id < b.src_id ||
                         (a.src_id == b.src_id && a.dst_id < b.dst_id);
              });

    edge_list_ = std::move(all_edges);

    //计算每个节点的出度并做前缀和
    row_ptr_.assign(n + 1, 0);
    for (const auto& e : edge_list_) {
        row_ptr_[e.src_id + 1]++;
    }
    for (int i = 0; i < n; i++) {
        row_ptr_[i + 1] += row_ptr_[i];
    }
}

//构建入边索引：in_row_ptr[i]为节点i入边起始下标
void Graph::build_in_index() {
    int n = node_count();
    int m = (int)edge_list_.size();

    in_row_ptr_.assign(n + 1, 0);
    for (const auto& e : edge_list_) {
        in_row_ptr_[e.dst_id + 1]++;
    }
    for (int i = 0; i < n; i++) {
        in_row_ptr_[i + 1] += in_row_ptr_[i];
    }

    //填充入边索引数组
    in_edge_idx_.resize(m);
    std::vector<int> cnt(n, 0);
    for (int k = 0; k < m; k++) {
        int dst = edge_list_[k].dst_id;
        in_edge_idx_[in_row_ptr_[dst] + cnt[dst]] = k;
        cnt[dst]++;
    }
}

//统计各节点的出/入流量
void Graph::compute_node_infos() {
    int n = node_count();
    node_infos_.resize(n);
    for (int i = 0; i < n; i++) {
        node_infos_[i].ip        = id_to_ip_[i];
        node_infos_[i].out_bytes = 0;
        node_infos_[i].in_bytes  = 0;
    }
    for (const auto& e : edge_list_) {
        node_infos_[e.src_id].out_bytes += e.total_bytes;
        node_infos_[e.dst_id].in_bytes  += e.total_bytes;
    }
}

//获取节点id的所有出边指针列表
std::vector<const Edge*> Graph::out_edges(int node_id) const {
    std::vector<const Edge*> result;
    if (node_id < 0 || node_id >= node_count()) return result;
    for (int k = row_ptr_[node_id]; k < row_ptr_[node_id + 1]; k++) {
        result.push_back(&edge_list_[k]);
    }
    return result;
}

//获取节点id的所有入边指针列表
std::vector<const Edge*> Graph::in_edges(int node_id) const {
    std::vector<const Edge*> result;
    if (node_id < 0 || node_id >= node_count()) return result;
    for (int k = in_row_ptr_[node_id]; k < in_row_ptr_[node_id + 1]; k++) {
        result.push_back(&edge_list_[in_edge_idx_[k]]);
    }
    return result;
}

//打印图的摘要信息
void Graph::print_summary() const {     
    std::cout << "           Graph summary                 \n"
              << "\n"
              << "  Node count: " << std::setw(27) << node_count() << " \n"
              << "  Edge count: " << std::setw(27) << edge_count()  << " \n";
}

//打印前max_nodes个节点的邻接表
void Graph::print_adjacency(int max_nodes) const {
    int limit = std::min(max_nodes, node_count());
    std::cout << "\n[Adjacency list (first " << limit << " nodes)]\n";
    for (int i = 0; i < limit; i++) {
        std::cout << "  " << std::setw(15) << std::left << id_to_ip_[i]
                  << " -> ";
        auto oes = out_edges(i);
        if (oes.empty()) {
            std::cout << "(no outgoing edges)";
        } else {
            for (const auto* e : oes) {
                std::cout << id_to_ip_[e->dst_id]
                          << "(bytes=" << e->total_bytes
                          << ", dur=" << std::fixed << std::setprecision(2)
                          << e->total_duration << "s)  ";
            }
        }
        std::cout << "\n";
    }
}