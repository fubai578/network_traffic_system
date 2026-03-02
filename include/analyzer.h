#ifndef ANALYZER_H
#define ANALYZER_H

#include "graph.h"
#include "types.h"
#include <vector>
#include <string>
#include <utility>

//网络流量分析器：流量排序、路径查找、星型检测、安全规则检查
class Analyzer {
public:
    explicit Analyzer(const Graph& g) : graph_(g) {}

    //流量排序
    void sort_nodes_by_traffic(int top_n = 0) const; //所有节点按总流量降序输出（top_n=0输出全部）
    void sort_https_nodes(int top_n = 0) const; //筛选HTTPS节点（TCP+443端口）按流量排序输出
    void sort_unidirectional_nodes(double threshold = 0.8, int top_n = 0) const; //筛选单向流量占比>阈值的节点

    //路径查找
    void find_min_congestion_path(const std::string& src_ip, const std::string& dst_ip) const; //Dijkstra找拥塞最小路径
    void find_min_hop_path(const std::string& src_ip, const std::string& dst_ip) const; //BFS找跳数最小路径
    void compare_paths(const std::string& src_ip, const std::string& dst_ip) const; //对比两条路径并输出

    //扩展功能
    void detect_star_topology() const; //检测星型拓扑（中心节点≥20个专属叶节点）
    void check_security_rule(const SecurityRule& rule) const; //根据安全规则检查违规会话

private:
    const Graph& graph_;

    std::string format_path(const std::vector<int>& path) const; //格式化路径为IP串（IP1->IP2->...）
    double path_congestion(const std::vector<int>& path) const; //计算路径总拥塞度（各边拥塞度之和）
    static unsigned int ip_to_uint(const std::string& ip); //IP转32位整数（便于范围比较）
};

#endif // ANALYZER_H