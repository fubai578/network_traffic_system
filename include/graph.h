#ifndef GRAPH_H
#define GRAPH_H

#include "types.h"
#include <vector>
#include <string>
#include <unordered_map>

//网络拓扑图（邻接表结构）
class Graph {
public:
    Graph() = default;

    //从原始会话记录构建图
    void build(const std::vector<SessionRecord>& records);

    //查询接口
    int node_count() const { return (int)id_to_ip_.size(); } //返回节点总数

    int edge_count() const { return (int)edge_list_.size(); } //返回边总数

    const std::string& ip_of(int id) const { return id_to_ip_.at(id); } //通过节点ID获取IP
    
    int id_of(const std::string& ip) const; //通过IP获取节点ID，不存在返回-1
    
    std::vector<const Edge*> out_edges(int node_id) const; //获取节点i的所有出边
    
    std::vector<const Edge*> in_edges(int node_id) const; //获取节点i的所有入边
    
    const std::vector<Edge>& edges() const { return edge_list_; } //获取全部边
    
    const NodeInfo& node_info(int id) const { return node_infos_.at(id); } //获取节点统计信息
    
    void print_summary() const; //打印图的摘要信息
    
    void print_adjacency(int max_nodes = 20) const; //打印邻接表（调试用）

private:
    //IP <-> 整数ID双向映射
    std::unordered_map<std::string, int> ip_to_id_;
    std::vector<std::string>             id_to_ip_;

    //CSR邻接表（row_ptr大小=node_count+1，edge_list按src_id排序）
    std::vector<int>  row_ptr_;
    std::vector<Edge> edge_list_;

    //入边索引（指向edge_list_的下标）
    std::vector<int>  in_row_ptr_;
    std::vector<int>  in_edge_idx_;

    //节点统计信息
    std::vector<NodeInfo> node_infos_;

    //获取或分配IP对应的节点ID
    int get_or_create_id(const std::string& ip);
    //构建CSR结构（所有边收集完毕后调用）
    void build_csr(std::unordered_map<std::string, Edge>& raw_edges);
    //构建入边索引
    void build_in_index();
    //统计各节点的出/入流量
    void compute_node_infos();
};

#endif //GRAPH_H