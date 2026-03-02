#ifndef UNION_FIND_H
#define UNION_FIND_H

#include <vector>
#include <unordered_map>
#include <string>

//并查集：快速管理连通子图，支持路径压缩+按秩合并
class UnionFind {
public:
    explicit UnionFind(int n);
    //查找节点x的根节点（路径压缩）
    int find(int x);

    //合并x和y所在集合（按秩合并），返回合并后的根节点
    int unite(int x, int y);

    //判断x和y是否在同一集合
    bool same(int x, int y);

    //获取包含节点x的所有节点（total_nodes为节点总数）
    std::vector<int> get_component(int x, int total_nodes);

private:
    std::vector<int> parent_; //父节点数组
    std::vector<int> rank_;   //秩数组（用于按秩合并）
};

#endif // UNION_FIND_H