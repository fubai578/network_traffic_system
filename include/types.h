#ifndef TYPES_H
#define TYPES_H

#include <string>
#include <map>
#include <vector>
#include <limits>

//协议编号到名称的映射
static const std::map<int, std::string> PROTOCOL_NAMES = {
    {1,  "ICMP"}, {6,  "TCP"}, {17, "UDP"},
    {47, "GRE"},  {50, "ESP"}, {51, "AH"},
    {89, "OSPF"}, {132,"SCTP"}
};

//原始会话记录（CSV读取的原始数据）
struct SessionRecord {
    std::string src_ip;       //源IP地址
    std::string dst_ip;       //目的IP地址
    int         protocol;     //协议编号
    int         src_port;     //源端口
    int         dst_port;     //目的端口
    long long   data_size;    //数据量
    double      duration;     //会话持续时间（秒）
};

//按协议统计的子流量信息
struct ProtocolStat {
    long long total_bytes;    //总字节数
    double    total_duration; //总持续时间
    int       session_count;  //会话次数
};

//合并后的有向边（两个IP间的聚合通信信息）
struct Edge {
    int           src_id;             //源节点ID
    int           dst_id;             //目的节点ID
    long long     total_bytes;        //总流量
    double        total_duration;     //总持续时间
    int           session_count;      //会话次数
    std::map<int, ProtocolStat> proto_stats; //各协议统计
    int           src_port;           //最后一次源端口
    int           dst_port;           //最后一次目的端口

    //计算拥塞程度=总流量/总持续时间（持续时间为0返回最大值）
    double congestion() const {
        if (total_duration < 1e-9) return std::numeric_limits<double>::max();
        return (double)total_bytes / total_duration;
    }
};

//节点信息：入/出流量统计
struct NodeInfo {
    std::string ip;           //IP地址
    long long   out_bytes;    //发出的总流量
    long long   in_bytes;     //接收的总流量
    long long total_bytes() const { return out_bytes + in_bytes; }
    double    out_ratio()   const {
        long long tot = total_bytes();
        return tot == 0 ? 0.0 : (double)out_bytes / tot;
    }
};

//安全规则类型：允许/禁止
enum class RuleAction { ALLOW, DENY };

//安全规则：源IP允许/禁止与指定IP范围通信
struct SecurityRule {
    std::string  src_ip;      //规则作用源IP
    std::string  range_start; //IP范围起始
    std::string  range_end;   //IP范围结束
    RuleAction   action;      //ALLOW/DENY
};

#endif // TYPES_H