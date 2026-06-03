from pathlib import Path

import pygraphviz as pgv


def main() -> None:
    root = Path(__file__).resolve().parent
    graph = pgv.AGraph(strict=False, directed=True)
    graph.graph_attr.update(rankdir="LR", label="PyGraphviz Test", labelloc="t")
    graph.node_attr.update(shape="box", style="rounded,filled", fillcolor="#eef6ff")
    graph.edge_attr.update(color="#4a6fa5")

    graph.add_edge("Install", "Import OK")
    graph.add_edge("Import OK", "Layout OK")
    graph.add_edge("Layout OK", "Render OK")

    dot_path = root / "pygraphviz_test.dot"
    png_path = root / "pygraphviz_test.png"
    svg_path = root / "pygraphviz_test.svg"

    graph.layout(prog="dot")
    graph.write(dot_path)
    graph.draw(png_path)
    graph.draw(svg_path)

    print(f"pygraphviz {pgv.__version__}")
    print(f"nodes={graph.number_of_nodes()} edges={graph.number_of_edges()}")
    print(f"dot={dot_path}")
    print(f"png={png_path}")
    print(f"svg={svg_path}")


if __name__ == "__main__":
    main()
