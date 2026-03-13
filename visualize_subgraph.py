"""
用法：python visualize_subgraph.py [json_path]
"""
import json, sys, os, webbrowser
import networkx as nx
from ipysigma import Sigma

def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def next_output_path(base_dir):
    """在 base_dir 下找下一个可用的 subgraph_N.html 序号"""
    os.makedirs(base_dir, exist_ok=True)
    seq = 1
    while os.path.exists(os.path.join(base_dir, f"subgraph_{seq}.html")):
        seq += 1
    return os.path.join(base_dir, f"subgraph_{seq}.html")

def build_graph(data):
    """把 JSON 数据转为 networkx 有向图，节点和边均携带属性"""
    G = nx.DiGraph()
    for node in data["nodes"]:
        G.add_node(node["id"], total_bytes=node["total_bytes"])
    for edge in data["edges"]:
        G.add_edge(edge["source"], edge["target"],
                   bytes=edge["bytes"],
                   protocol=edge.get("protocol", "?"),
                   sessions=edge["sessions"])
    return G

def main():
    json_path = sys.argv[1] if len(sys.argv) > 1 else "subgraph_data.json"
    if not os.path.exists(json_path):
        print(f"[Error] Not found: {json_path}", file=sys.stderr)
        sys.exit(1)

    data = load_json(json_path)
    query_ip = data["query_ip"]
    G = build_graph(data)

    #查询节点标红，其余节点统一深蓝
    node_colors = {node: "#c0392b" if node == query_ip else "#2c5282"
                   for node in G.nodes()}

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = next_output_path(os.path.join(script_dir, "graph"))

    #ipysigma 直接将 networkx 图导出为独立 HTML，交互和布局由库负责
    Sigma.write_html(
        G,
        output_path,
        fullscreen=True,
        node_size=nx.get_node_attributes(G, "total_bytes"),  #节点大小与流量成比例
        node_color=node_colors,                              #查询节点高亮红色
        node_size_range=(4, 20),
        default_edge_type="arrow",                           #有向箭头边
        node_label_size=nx.get_node_attributes(G, "total_bytes"),
    )

    print(f"[Visualize] Saved: {output_path}")
    webbrowser.open(f"file:///{os.path.abspath(output_path)}")

if __name__ == "__main__":
    main()