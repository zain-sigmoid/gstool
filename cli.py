# cli.py
from __future__ import annotations
import argparse, asyncio, json, os, sys, tempfile
from pathlib import Path
from dataclasses import is_dataclass, asdict
from tqdm import tqdm
from termcolor import colored, cprint
from typing import List, Optional, Set
from core.interfaces import analyzer_registry
from utils.prod_shift import Extract
from core.models import AnalysisConfiguration, SeverityLevel
from core.engine import (
    UnifiedAnalysisEngine as Engine,
)

from analyzers.robustness_analyzer import RobustnessAnalyzer
from analyzers.pii_analyzer import PIIAnalyzer
from analyzers.testability_analyzer import TestabilityAnalyzer
from analyzers.observability_analyzer import ObservabilityAnalyzer
from analyzers.readability_analyzer import ReadabilityAnalyzer
from analyzers.injection_analyzer import InjectionAnalyzer
from analyzers.maintainability_analyzer import MaintainabilityAnalyzer
from analyzers.performance_analyzer import PerformanceAnalyzer
from analyzers.compliance_analyzer import ComplianceAnalyzer
from analyzers.secrets_analyzer import HardcodedSecretsAnalyzer


def initialize_analyzers() -> None:
    """Register all analyzers in the global registry."""
    analyzer_registry.register(HardcodedSecretsAnalyzer())
    analyzer_registry.register(RobustnessAnalyzer())
    analyzer_registry.register(PIIAnalyzer())
    analyzer_registry.register(TestabilityAnalyzer())
    analyzer_registry.register(ObservabilityAnalyzer())
    analyzer_registry.register(ReadabilityAnalyzer())
    analyzer_registry.register(InjectionAnalyzer())
    analyzer_registry.register(MaintainabilityAnalyzer())
    analyzer_registry.register(PerformanceAnalyzer())
    analyzer_registry.register(ComplianceAnalyzer())


def write_json_file(path: str, data: dict, *, compact: bool) -> None:
    out_dir = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(out_dir, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", delete=False, dir=out_dir, encoding="utf-8"
    ) as tf:
        tmp = tf.name
        if compact:
            json.dump(
                data,
                tf,
                ensure_ascii=False,
                separators=(",", ":"),
                default=_json_default,
            )
        else:
            json.dump(data, tf, ensure_ascii=False, indent=2, default=_json_default)
            tf.write("\n")
    os.replace(tmp, path)


def _json_default(o):
    """Fallback converter for non-serializable types."""
    import datetime, pathlib, enum, dataclasses

    if isinstance(o, datetime.datetime):
        return o.isoformat()
    if isinstance(o, datetime.date):
        return o.isoformat()
    if isinstance(o, (pathlib.Path,)):
        return str(o)
    if isinstance(o, (set, frozenset)):
        return list(o)
    if isinstance(o, enum.Enum):
        return o.value
    if dataclasses.is_dataclass(o):
        return dataclasses.asdict(o)

    # Try model_dump, to_dict, dict, json (Pydantic, etc.)
    for attr in ("to_dict", "dict", "model_dump", "json"):
        if hasattr(o, attr) and callable(getattr(o, attr)):
            try:
                v = getattr(o, attr)()
                if isinstance(v, str):
                    return json.loads(v)
                return v
            except Exception:
                pass

    return str(o)


def collect_code_files(target_path: str, *, exts: set[str] | None = None) -> list[str]:
    """Return a list of code files under target_path using Extract's filters."""
    exts = exts or set(Extract.CODE_EXTS)
    root = Path(target_path).resolve()

    # Let Extract decide the best project root (handles wrapper dirs)
    project_root = Extract.find_best_project_root(root, exts)
    count = Extract.count_code_files(project_root, exts)

    files: list[str] = []
    # Manual stack walk so we can prune hidden/excluded dirs eagerly
    stack: list[Path] = [project_root]
    while stack:
        d = stack.pop()
        try:
            for entry in d.iterdir():
                if entry.is_dir():
                    if not Extract.is_hidden_dir(entry):
                        stack.append(entry)
                else:
                    if Extract.is_code_file(entry, exts):
                        files.append(str(entry))
        except PermissionError:
            # ignore unreadable dirs
            continue
    return files, count


def eprint(msg: str, *, end: str = "\n"):
    print(msg, file=sys.stderr, end=end, flush=True)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    # First parse only --list-analyzers to detect it early
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--list-analyzers", action="store_true")
    known, _ = pre.parse_known_args(argv)

    p = argparse.ArgumentParser(
        prog="sigscan",
        description="Run signature scanning/analysis over a path with a configurable setup.",
    )
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to analyze. By default scan the current folder from terminal",
    )
    p.add_argument(
        "-a",
        "--analyzer",
        action="append",
        default=[],
        help="Enable only these analyzers (repeatable, by name).",
    )
    p.add_argument(
        "--all-analyzers", action="store_true", help="Enable all available analyzers."
    )
    p.add_argument("--parallel", action="store_true")
    p.add_argument("--include-low-confidence", action="store_true")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--max-findings", type=int, default=500)
    p.add_argument(
        "-o",
        "--out",
        metavar="FILE",
        help="Write JSON result to FILE (no stdout on success).",
    )
    p.add_argument("--compact", action="store_true", help="Minified JSON.")
    p.add_argument("--no-progress", action="store_true")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument(
        "--list-analyzers",
        action="store_true",
        help="List available analyzers and exit.",
    )

    # only enforce -o/--out if we are not listing analyzers
    args = p.parse_args(argv)
    if not args.list_analyzers and not args.out:
        p.error("the following arguments are required: -o/--out")
    return args


class TqdmProgress:
    """Adapter that matches engine's progress_cb signature."""

    def __init__(self, show: bool, desc: str = "Analyzing"):
        self.bar = tqdm(
            total=1,  # never zero
            desc=desc,
            unit="",
            ncols=100,
            dynamic_ncols=True,
            leave=True,
            disable=not show,
            colour="cyan",  # visible bar color
            bar_format="{desc} {n_fmt}/{total_fmt} |{bar}| {elapsed}<{remaining}",
        )
        self.total_known = False

    def __call__(self, increment=1, stage=None, total_analyzers=None):
        if total_analyzers is not None and not self.total_known:
            self.bar.total = max(1, int(total_analyzers))
            self.total_known = True
            self.bar.refresh()
        if stage:
            if "finished" in stage:
                color = "green"
            elif "running" in stage:
                color = "yellow"
            else:
                color = "cyan"
            self.bar.set_description_str(colored(f"[{stage}]", color, attrs=["bold"]))
        if increment:
            self.bar.update(increment)

    def close(self):
        self.bar.close()


# return report
async def _run_async(engine, cfg, show_progress: bool):
    tprog = TqdmProgress(show_progress, desc=colored("[starting]", "cyan"))
    try:
        report = await engine.analyze(cfg, progress_cb=tprog)
    finally:
        tprog.close()
    return report


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    exts = set(Extract.CODE_EXTS)
    initialize_analyzers()
    if args.list_analyzers:
        for (
            name
        ) in (
            analyzer_registry.list_analyzer_names()
        ):  # implement list_names() on your registry if not present
            print(name)
        return 0
    target_path = os.path.abspath(args.path)
    reader_files, count = collect_code_files(target_path)
    cprint(
        f"Total Files for Analysis : {count}",
        "yellow",
    )
    if not reader_files:
        cprint("⚠️ No Python files found after filtering.", "yellow")
        return 0

    if not os.path.exists(target_path):
        eprint(f"Error: path not found: {target_path}")
        return 2

    # Build configuration equivalent to Streamlit
    enabled_analyzers: Set[str] = set(args.analyzer or [])
    if args.all_analyzers:
        try:
            if Engine and hasattr(Engine, "available_analyzers"):
                enabled_analyzers = set(Engine.available_analyzers())  # type: ignore[attr-defined]
        except Exception:
            # Fallback: keep whatever user passed
            pass

    cfg = AnalysisConfiguration(
        target_path=target_path,
        enabled_analyzers=enabled_analyzers,
        severity_threshold=SeverityLevel.INFO,  # match Streamlit: capture all severities
        parallel_execution=bool(args.parallel),
        include_low_confidence=bool(args.include_low_confidence),
        timeout_seconds=int(args.timeout),
        max_findings_per_analyzer=int(args.max_findings),
        files=reader_files,
    )

    # Get engine (mirror what your Streamlit app builds)
    # If your app constructs engine via a factory, import and call it here.
    try:
        if Engine is None:
            raise ImportError("Engine import path not set. Update cli.py imports.")
        engine = Engine()  # adjust if needs params
    except Exception as e:
        eprint(f"Error: cannot construct analysis engine: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    # Run analysis (async)
    try:
        report = asyncio.run(
            _run_async(engine, cfg, show_progress=not args.no_progress)
        )
    except KeyboardInterrupt:
        eprint("Interrupted.")
        return 130
    except Exception as e:
        eprint(f"Error during analysis: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    # Serialize
    try:
        if hasattr(report, "to_dict"):
            payload = report.to_dict()  # type: ignore
        elif is_dataclass(report):
            payload = asdict(report)  # type: ignore
        else:
            # Try common attributes; otherwise convert generically
            payload = (
                report.model_dump()
                if hasattr(report, "model_dump")
                else (
                    report.dict()
                    if hasattr(report, "dict")
                    else (
                        json.loads(report.json())
                        if hasattr(report, "json")
                        else (
                            report.__dict__
                            if hasattr(report, "__dict__")
                            else {"result": report}
                        )
                    )
                )
            )
    except Exception:
        # last-resort generic conversion
        payload = {"result": report}

    # Write JSON file
    try:
        write_json_file(args.out, payload, compact=args.compact)
        cprint(f"✅ Findings saved to {args.out}", "green", attrs=["bold"])
    except Exception as e:
        cprint(
            f"❌ Failed to write output file '{args.out}': {e}", "red", attrs=["bold"]
        )
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    # Success: no stdout output as requested
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
