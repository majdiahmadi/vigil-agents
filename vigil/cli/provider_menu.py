from getpass import getpass

from rich.console import Console

from vigil.llm.provider_registry import PROVIDERS

console = Console()


def manage_credentials(credentials) -> None:
    console.print("Provider credentials are read from environment variables or the OS credential manager.")
    for index, provider in enumerate(PROVIDERS.values(), 1):
        console.print(f"  {index}. {provider.display_name}: {'configured' if credentials.get(provider.provider_id) else 'missing'}")
    try:
        answer = console.input("Provider number to save/update (B to cancel): ").strip()
    except (EOFError, KeyboardInterrupt):
        return
    if answer.lower() == "b" or not answer.isdigit() or not 1 <= int(answer) <= len(PROVIDERS):
        return
    provider = list(PROVIDERS.values())[int(answer) - 1]
    try:
        secret = getpass(f"{provider.display_name} API key (hidden): ")
        if secret:
            persisted = credentials.save(provider.provider_id, secret)
            if persisted:
                console.print("Credential saved in the OS credential manager.")
            else:
                console.print("[yellow]Credential manager unavailable. Key retained for this process only; use an environment variable for future sessions.[/yellow]")
    except (EOFError, KeyboardInterrupt):
        return

