#include "../include/union_find.h"
#include <algorithm>

//初始化并查集，n为节点数量
UnionFind::UnionFind(int n) : parent_(n), rank_(n, 0) {
    for (int i = 0; i < n; i++) parent_[i] = i;
}

//查找根节点（路径压缩优化）
int UnionFind::find(int x) {
    if (parent_[x] != x)
        parent_[x] = find(parent_[x]); //路径压缩
    return parent_[x];
}

//合并两个集合（按秩合并优化）
int UnionFind::unite(int x, int y) {
    int rx = find(x), ry = find(y);
    if (rx == ry) return rx;
    //按秩合并：秩小的树挂到秩大的树下
    if (rank_[rx] < rank_[ry]) std::swap(rx, ry);
    parent_[ry] = rx;
    if (rank_[rx] == rank_[ry]) rank_[rx]++;
    return rx;
}

//判断x和y是否属于同一连通分量
bool UnionFind::same(int x, int y) {
    return find(x) == find(y);
}

//获取与节点x同一连通分量的所有节点
std::vector<int> UnionFind::get_component(int x, int total_nodes) {
    int root = find(x);
    std::vector<int> comp;
    for (int i = 0; i < total_nodes; i++) {
        if (find(i) == root) comp.push_back(i);
    }
    return comp;
}