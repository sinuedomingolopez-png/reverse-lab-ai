"""Offline report comparison and optional local LLM interpretation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .reports import compare_reports, explain_comparison, explain_report, load_report


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text.rstrip() + "\n", encoding="utf-8")
    else:
        print(text)


def main_compare(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Compare two saved Reverse Lab AI JSON reports")
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--format", choices=("json","text"), default="json")
    parser.add_argument("--output", help="Output file; print to console when omitted")
    args = parser.parse_args(argv)
    comparison=compare_reports(load_report(args.left), load_report(args.right))
    result=(json.dumps(comparison,ensure_ascii=False,indent=2) if args.format=="json"
            else explain_comparison(comparison))
    _write(result,args.output)


def main_explain(argv=None) -> None:
    parser=argparse.ArgumentParser(description="Explain a report offline, or optionally with local Ollama")
    parser.add_argument("report",type=Path)
    parser.add_argument("--ollama",action="store_true",help="Explicitly contact localhost Ollama")
    parser.add_argument("--model",default="qwen2.5:3b")
    parser.add_argument("--output")
    args=parser.parse_args(argv)
    report=load_report(args.report)
    if args.ollama:
        from .ollama_adapter import explain_with_ollama
        result=explain_with_ollama(report,model=args.model)
    else:
        result=explain_report(report)
    _write(result,args.output)


def main(argv=None) -> None:
    parser=argparse.ArgumentParser(description="Reverse Lab AI report tools")
    parser.add_argument("command",choices=("compare","explain"))
    known, remainder=parser.parse_known_args(argv)
    if known.command=="compare":
        main_compare(remainder)
    else:
        main_explain(remainder)


if __name__=="__main__":
    main()
