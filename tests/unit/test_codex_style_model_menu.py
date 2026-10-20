from io import StringIO

from rich.console import Console

import vigil.cli.model_menu as model_menu
import vigil.cli.terminal_menu as terminal_menu
from vigil.cli.model_menu import CatalogState
from vigil.cli.terminal_menu import MenuOption
from vigil.llm.model_catalog import ModelInfo


def models(count: int = 30):
    return [ModelInfo(f"model-{index:02}", f"Model {index:02}", "test", {}) for index in range(1, count + 1)]


def test_catalog_state_search_navigation_and_number_selection():
    state = CatalogState(models(), page_size=10)
    state.change_page(1)
    assert state.page == 1 and state.visible[0].model_id == "model-11"
    state.set_query("model-2")
    assert len(state.filtered) == 10
    state.number_buffer = "4"
    assert state.numbered_selection().model_id == "model-23"
    state.move(1)
    assert state.number_buffer == ""


def test_keyboard_option_menu_uses_arrows_and_enter(monkeypatch):
    output = StringIO()
    test_console = Console(file=output, force_terminal=True, width=100)
    keys = iter(["down", "enter"])
    monkeypatch.setattr(terminal_menu, "is_interactive", lambda console: True)
    chosen = terminal_menu.choose_option(
        test_console, "Models", "Choose", [MenuOption("one", "One"), MenuOption("two", "Two")],
        key_reader=lambda: next(keys),
    )
    assert chosen == "two"


def test_model_browser_accepts_multi_digit_number(monkeypatch):
    output = StringIO()
    test_console = Console(file=output, force_terminal=True, width=120)
    keys = iter(["1", "5", "enter"])
    monkeypatch.setattr(model_menu, "console", test_console)
    monkeypatch.setattr(model_menu, "is_interactive", lambda console: True)
    selected = model_menu.browse_catalog(models(30), "Provider", "triage", "model-01", False, key_reader=lambda: next(keys))
    assert selected.model_id == "model-15"


def test_offline_assignment_can_be_restored(registry):
    manager = registry.dependencies.model_manager
    manager.assign("triage", "openai", "gpt-test")
    manager.assign("triage", "offline", "deterministic-readonly-v1")
    assert manager.assignment("triage") == ("offline", "deterministic-readonly-v1")

