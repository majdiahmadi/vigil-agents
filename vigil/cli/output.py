import json

from rich.console import Console
from rich.syntax import Syntax

console = Console()


def print_json(value) -> None:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    text = json.dumps(value, indent=2, default=str)
    console.print(Syntax(text, "json", word_wrap=True))

