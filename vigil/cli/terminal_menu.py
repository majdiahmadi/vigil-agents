from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Callable, Sequence

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


@dataclass(frozen=True, slots=True)
class MenuOption:
    value: str
    label: str
    detail: str = ""
    current: bool = False


def read_key() -> str:
    """Read one navigation key without requiring a full-screen TUI."""
    if os.name == "nt":
        import msvcrt

        char = msvcrt.getwch()
        if char in {"\x00", "\xe0"}:
            return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(msvcrt.getwch(), "")
        return {"\r": "enter", "\x1b": "escape", "\x08": "backspace"}.get(char, char)

    import select
    import termios
    import tty

    descriptor = sys.stdin.fileno()
    previous = termios.tcgetattr(descriptor)
    try:
        tty.setraw(descriptor)
        char = sys.stdin.read(1)
        if char == "\x1b":
            sequence = ""
            while select.select([sys.stdin], [], [], 0.01)[0]:
                sequence += sys.stdin.read(1)
            return {"[A": "up", "[B": "down", "[D": "left", "[C": "right"}.get(sequence, "escape")
        return {"\r": "enter", "\n": "enter", "\x7f": "backspace"}.get(char, char)
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, previous)


def is_interactive(console: Console) -> bool:
    return bool(console.is_terminal and sys.stdin.isatty())


def _option_panel(title: str, subtitle: str, options: Sequence[MenuOption], cursor: int) -> Panel:
    table = Table.grid(padding=(0, 1))
    table.add_column(width=2)
    table.add_column(ratio=2)
    table.add_column(ratio=4)
    for index, option in enumerate(options):
        selected = index == cursor
        pointer = ">" if selected else " "
        label = Text(option.label, style="bold cyan" if selected else "white")
        if option.current:
            label.append("  current", style="green")
        detail = Text(option.detail, style="bright_black" if not selected else "cyan")
        table.add_row(pointer, label, detail)
    footer = Text("Up/Down move   Enter select   1-9 quick select   Esc back", style="bright_black")
    return Panel(Group(Text(subtitle, style="bright_black"), Text(""), table, Text(""), footer), title=f"[bold]{title}[/bold]", border_style="cyan", padding=(1, 2))


def choose_option(
    console: Console,
    title: str,
    subtitle: str,
    options: Sequence[MenuOption],
    *,
    key_reader: Callable[[], str] = read_key,
) -> str | None:
    if not options:
        return None
    if not is_interactive(console):
        console.print(f"\n[bold]{title}[/bold]\n[bright_black]{subtitle}[/bright_black]")
        for index, option in enumerate(options, 1):
            marker = " [current]" if option.current else ""
            console.print(f"  {index}. {option.label}{marker}  [bright_black]{option.detail}[/bright_black]")
        try:
            answer = console.input("Choose by number (B to go back): ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if answer.lower() == "b":
            return None
        return options[int(answer) - 1].value if answer.isdigit() and 1 <= int(answer) <= len(options) else None

    cursor = next((index for index, option in enumerate(options) if option.current), 0)
    with Live(_option_panel(title, subtitle, options, cursor), console=console, transient=True, refresh_per_second=20) as live:
        while True:
            key = key_reader()
            if key in {"up", "k"}:
                cursor = (cursor - 1) % len(options)
            elif key in {"down", "j"}:
                cursor = (cursor + 1) % len(options)
            elif key == "enter":
                return options[cursor].value
            elif key in {"escape", "q", "b"}:
                return None
            elif len(key) == 1 and key.isdigit() and key != "0" and int(key) <= len(options):
                return options[int(key) - 1].value
            live.update(_option_panel(title, subtitle, options, cursor))

