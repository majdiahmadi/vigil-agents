import pytest


@pytest.mark.asyncio
async def test_chat_uses_user_history_without_creating_case(registry, monkeypatch):
    captured = {}

    class FakeAdapter:
        async def chat(self, *, messages, instructions):
            captured["messages"] = messages
            captured["instructions"] = instructions
            return "A conversational answer"

    monkeypatch.setattr(registry.dependencies.model_manager, "adapter_for", lambda agent_id: FakeAdapter())
    before = registry.dependencies.store.list_cases()
    response = await registry.create("triage").chat_message("What evidence would establish authorization?", [{"role": "user", "content": "Earlier question"}, {"role": "assistant", "content": "Earlier answer"}])
    after = registry.dependencies.store.list_cases()
    assert response == "A conversational answer"
    assert captured["messages"][-1]["content"] == "What evidence would establish authorization?"
    assert captured["messages"][0]["content"] == "Earlier question"
    assert before == after


@pytest.mark.asyncio
async def test_offline_chat_is_explicitly_unavailable(registry):
    with pytest.raises(RuntimeError, match="AI chat is unavailable"):
        await registry.create("hunter").chat_message("Hello")
