KNOWN_TOOL_CAPABLE_PREFIXES = ("gpt-", "deepseek-chat", "meta/llama", "mistral", "qwen")


def tool_capability(model_id: str) -> str:
    lower = model_id.lower()
    return "likely" if any(part in lower for part in KNOWN_TOOL_CAPABLE_PREFIXES) else "unknown"

