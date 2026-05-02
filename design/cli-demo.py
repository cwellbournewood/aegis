"""Render a representative AEGIS CLI session as SVG.

Used to generate docs/images/cli.png (via the SVG export). Not used at runtime.
"""
from rich.console import Console
from rich.table import Table

from aegis.cli import AEGIS_THEME, _BANNER, _BOX_ASCII

console = Console(theme=AEGIS_THEME, record=True, width=104, force_terminal=True)


def render_demo() -> None:
    console.print(_BANNER.format(ver="0.9.0"))
    console.print("[label]listening[/label]  [bronze.bright]http://0.0.0.0:8080[/bronze.bright]")
    console.print("[label]policy[/label]     ./policies/balanced.yml")
    console.print("[label]dashboard[/label]  [bronze]http://0.0.0.0:8080/aegis/dashboard[/bronze]")
    console.print()

    # --- bench results ---
    t = Table(
        title="-- Adversarial Corpus Benchmark . mode=balanced --",
        box=_BOX_ASCII,
        border_style="rule",
        header_style="table.header",
        title_style="table.title",
    )
    t.add_column("category", style="bronze")
    t.add_column("attempts", justify="right", style="parchment.dim")
    t.add_column("blocked", justify="right")
    t.add_column("warned", justify="right")
    t.add_column("allowed", justify="right")
    t.add_column("block rate", justify="right", style="bronze.bright")
    rows = [
        ("direct",      "4",  "[block]4[/block]", "[warn]0[/warn]", "[allow]0[/allow]", "100.0%"),
        ("indirect",    "8",  "[block]7[/block]", "[warn]0[/warn]", "[allow]1[/allow]", "87.5%"),
        ("memory",      "3",  "[block]3[/block]", "[warn]0[/warn]", "[allow]0[/allow]", "100.0%"),
        ("multi-agent", "2",  "[block]2[/block]", "[warn]0[/warn]", "[allow]0[/allow]", "100.0%"),
        ("benign",      "4",  "[block]0[/block]", "[warn]0[/warn]", "[allow]4[/allow]", "0.0%"),
    ]
    for r in rows:
        t.add_row(*r)
    t.add_section()
    t.add_row(
        "[title]ALL[/title]",
        "[title]21[/title]",
        "[block]16[/block]",
        "[warn]0[/warn]",
        "[allow]5[/allow]",
        "[bronze.bright]76.2%[/bronze.bright]",
    )
    console.print(t)
    console.print()

    # --- log tail ---
    t = Table(show_lines=False, box=_BOX_ASCII, border_style="rule", header_style="table.header")
    t.add_column("#", style="subtle", justify="right")
    t.add_column("decision")
    t.add_column("upstream", style="bronze")
    t.add_column("session", style="subtle")
    t.add_column("request", style="subtle")
    t.add_column("reason", style="parchment.dim")
    rows2 = [
        ("14832", "[block]BLOCK[/block]", "anthropic", "ses_4f2a2c8b", "req_01H8Y3K9", "L0 cannot authorize tool calls"),
        ("14831", "[allow]ALLOW[/allow]", "anthropic", "ses_4f2a2c8b", "req_01H8X8M2", "all gates ALLOW"),
        ("14830", "[allow]ALLOW[/allow]", "anthropic", "ses_4f2a2c8b", "req_01H8X7P4", "all gates ALLOW"),
        ("14829", "[warn]WARN[/warn]",   "openai",    "ses_8c1e7f2d", "req_01H8Z1A0", "intent drift below threshold"),
        ("14828", "[allow]ALLOW[/allow]", "openai",    "ses_8c1e7f2d", "req_01H902B9", "all gates ALLOW"),
        ("14827", "[block]BLOCK[/block]", "anthropic", "ses_a1b2c3d4", "req_01H903F1", "canary leak detected"),
    ]
    for r in rows2:
        t.add_row(*r)
    console.print(t)


if __name__ == "__main__":
    render_demo()
    console.save_svg(
        "docs/images/cli.svg",
        title="AEGIS CLI",
        font_aspect_ratio=0.55,
    )
    console.save_html("design/cli-demo-rendered.html", inline_styles=True)
    print("wrote docs/images/cli.svg and design/cli-demo-rendered.html")
