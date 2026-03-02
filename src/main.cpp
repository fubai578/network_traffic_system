/*功能菜单:
 *   1. 加载CSV文件并构建拓扑图
 *   2. 显示拓扑图概要信息
 *   3. 按流量大小排序节点
 *   4. 排序HTTPS通信节点
 *   5. 排序单向通信节点
 *   6. 路径搜索（最小拥塞 & 最小跳数）
 *   7. 检测星型拓扑结构
 *   8. 安全规则检查
 *   0. 退出程序
 */
#include <windows.h>
#include "csv_reader.h"
#include "graph.h"
#include "analyzer.h"
#include "types.h"
#include <iostream>
#include <string>
#include <limits>

//UI辅助函数
static void print_banner() {
    std::cout << "\n";
    std::cout << "      Network Traffic Analysis & Anomaly Detection    \n";
    std::cout << "\n";
}

//暂停提示函数，等待用户按回车继续
static void pause_prompt() {
    std::cout << "\n[Press Enter to continue...]";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
}

int main(int argc, char* argv[]) {
    //设置控制台输出编码为UTF-8，避免中文乱码
    SetConsoleOutputCP(CP_UTF8);
    print_banner();

    //支持从命令行参数指定CSV文件路径，默认路径为data/network_data.csv
    std::string csv_path = "data/network_data.csv";
    if (argc > 1) csv_path = argv[1];

    //全局状态变量
    std::vector<SessionRecord> records;  //存储从CSV加载的网络会话记录
    Graph graph;                         //网络拓扑图对象
    bool loaded = false;                 //标记数据是否已成功加载

    int choice = -1;
    while (choice != 0) {

        //处理输入异常（如用户输入非数字），清空错误状态并忽略无效输入
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }

        switch (choice) {
        //--------- 1. 加载CSV文件并构建拓扑图 ---------
        case 1: {
            std::cout << "CSV file path [default: " << csv_path << "]: ";
            std::cin.ignore();  //忽略输入缓冲区中残留的换行符
            std::string input;
            std::getline(std::cin, input);
            //如果用户输入了新路径，则更新CSV路径
            if (!input.empty()) csv_path = input;

            //清空原有数据，避免数据叠加
            records.clear();
            //加载CSV文件数据到records容器
            bool ok = CsvReader::load(csv_path, records);
            if (!ok || records.empty()) {
                std::cout << "[Error] Failed to load data, please check file path.\n";
                break;
            }
            //重新初始化拓扑图并基于加载的记录构建图
            graph = Graph();
            graph.build(records);
            loaded = true;
            std::cout << "\n✓ Data loaded and graph built successfully!\n";
            break;
        }

        //--------- 2. 显示拓扑图概要信息 ---------
        case 2: {
            //检查数据是否已加载，未加载则提示用户先执行选项1
            if (!loaded) { std::cout << "Please load data first (option 1).\n"; break; }
            //打印拓扑图的核心概要信息（节点数、边数等）
            graph.print_summary();
            std::cout << "\nPrint adjacency list? (1=yes / 0=no): ";
            int show_adj; std::cin >> show_adj;
            if (show_adj) {
                std::cout << "Show how many nodes (default 20): ";
                int max_n; std::cin >> max_n;
                //验证输入的节点数量，无效则使用默认值20
                if (max_n <= 0) max_n = 20;
                //打印指定数量节点的邻接表
                graph.print_adjacency(max_n);
            }
            break;
        }

        //--------- 3. 按流量大小排序节点 ---------
        case 3: {
            if (!loaded) { std::cout << "Please load data first (option 1).\n"; break; }
            std::cout << "Show top N (0=all): ";
            int topn; std::cin >> topn;
            //创建分析器对象，调用按流量排序节点的方法
            Analyzer(graph).sort_nodes_by_traffic(topn);
            break;
        }

        //--------- 4. 排序HTTPS通信节点 ---------
        case 4: {
            if (!loaded) { std::cout << "Please load data first (option 1).\n"; break; }
            std::cout << "Show top N (0=all): ";
            int topn; std::cin >> topn;
            //创建分析器对象，调用排序HTTPS节点的方法
            Analyzer(graph).sort_https_nodes(topn);
            break;
        }

        //--------- 5. 排序单向通信节点 ---------
        case 5: {
            if (!loaded) { std::cout << "Please load data first (option 1).\n"; break; }
            std::cout << "Outgoing ratio threshold (default 0.8 = 80%): ";
            double thresh; std::cin >> thresh;
            //验证阈值范围（0~1），无效则使用默认值0.8
            if (thresh <= 0 || thresh > 1) thresh = 0.8;
            std::cout << "Show top N (0=all): ";
            int topn; std::cin >> topn;
            //创建分析器对象，调用排序单向通信节点的方法
            Analyzer(graph).sort_unidirectional_nodes(thresh, topn);
            break;
        }

        //--------- 6. 路径搜索 ---------
        case 6: {
            if (!loaded) { std::cout << "Please load data first (option 1).\n"; break; }
            std::string src, dst;
            std::cout << "Enter source IP: ";
            std::cin >> src;
            std::cout << "Enter destination IP: ";
            std::cin >> dst;

            //创建分析器对象，比较最小拥塞路径和最小跳数路径
            Analyzer ana(graph);
            ana.compare_paths(src, dst);
            break;
        }

        //--------- 7. 检测星型拓扑结构 ---------
        case 7: {
            if (!loaded) { std::cout << "Please load data first (option 1).\n"; break; }
            //创建分析器对象，检测网络中的星型拓扑结构
            Analyzer(graph).detect_star_topology();
            break;
        }

        //--------- 8. 安全规则检查 ---------
        case 8: {
            if (!loaded) { std::cout << "Please load data first (option 1).\n"; break; }
            SecurityRule rule;
            std::cout << "Enter rule source IP (addr1): ";
            std::cin >> rule.src_ip;
            std::cout << "Enter IP range start (addr2): ";
            std::cin >> rule.range_start;
            std::cout << "Enter IP range end (addr3): ";
            std::cin >> rule.range_end;
            std::cout << "Rule action (1=DENY / 0=ALLOW): ";
            int action_type; std::cin >> action_type;
            //根据用户输入设置规则动作（拒绝/允许）
            rule.action = (action_type == 1) ? RuleAction::DENY : RuleAction::ALLOW;
            //创建分析器对象，检查该安全规则是否被违反
            Analyzer(graph).check_security_rule(rule);
            break;
        }
        //--------- 0. 退出程序 ---------
        case 0:
            std::cout << "\nThanks for using the Network Traffic Analysis & Anomaly Detection System!\n";
            break;
        //无效选项处理
        default:
            std::cout << "Invalid choice, please try again.\n";
        }
    }
    return 0;
}