from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from backend.app.agent.nodes import create_container, detect_stack, extract, llm_review, report, risk_validate, static_scan, taint_analysis
from backend.app.agent.state import AuditState


def build_audit_graph():
    graph = StateGraph(AuditState)
    graph.add_node("ExtractProject", extract.run)
    graph.add_node("DetectStack", detect_stack.run)
    graph.add_node("CreateSandbox", create_container.run)
    graph.add_node("StaticScan", static_scan.run)
    graph.add_node("TaintAnalysis", taint_analysis.run)
    graph.add_node("LLMReview", llm_review.run)
    graph.add_node("RiskValidate", risk_validate.run)
    graph.add_node("GenerateReport", report.run)

    graph.add_edge(START, "ExtractProject")
    graph.add_edge("ExtractProject", "DetectStack")
    graph.add_edge("DetectStack", "CreateSandbox")
    graph.add_edge("CreateSandbox", "StaticScan")
    graph.add_edge("StaticScan", "TaintAnalysis")
    graph.add_edge("TaintAnalysis", "LLMReview")
    graph.add_edge("LLMReview", "RiskValidate")
    graph.add_edge("RiskValidate", "GenerateReport")
    graph.add_edge("GenerateReport", END)
    return graph.compile()
