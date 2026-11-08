#!/usr/bin/env python3
"""Plot a bench stage: per-block transactions by account class and the per-second timeline.

    uv run python bench/plot_blocks.py OUT_DIR/stage-pq-relay-250 [--html report.html]

Writes an interactive HTML file next to the stage data (plotly is a tostester dependency).
"""

import argparse
import csv
from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots


def read(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("stage", type=Path, help="a stage-* directory written by run_local_bench.py")
    p.add_argument("--html", type=Path)
    a = p.parse_args()
    blocks, timeline = read(a.stage / "blocks.csv"), read(a.stage / "timeline.csv")
    if not blocks or not timeline:
        raise SystemExit("stage has no block or timeline rows")
    classes = [c for c in blocks[0] if c not in ("seqno", "gen_utime", "observed", "total_tx")]
    t0 = float(blocks[0]["observed"])
    fig = make_subplots(
        rows=2,
        cols=1,
        shared_xaxes=False,
        vertical_spacing=0.12,
        subplot_titles=("Transactions per basechain block", "Per second"),
    )
    x = [float(b["observed"]) - t0 for b in blocks]
    for c in classes:
        fig.add_trace(go.Bar(x=x, y=[int(b[c]) for b in blocks], name=c), row=1, col=1)
    seconds = [int(r["second"]) for r in timeline]
    for column in [c for c in timeline[0] if c != "second"]:
        fig.add_trace(
            go.Scatter(x=seconds, y=[int(r[column]) for r in timeline], name=column, mode="lines"),
            row=2,
            col=1,
        )
    fig.update_layout(barmode="stack", title=a.stage.name, height=800)
    fig.update_xaxes(title_text="seconds since first scanned block", row=1, col=1)
    fig.update_xaxes(title_text="seconds since first send", row=2, col=1)
    out = a.html or a.stage / "plot.html"
    fig.write_html(out, include_plotlyjs="cdn")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
