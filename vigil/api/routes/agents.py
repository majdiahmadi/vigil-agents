from fastapi import APIRouter, Depends, Request

from vigil.api.auth import require_bearer

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_bearer)])


@router.get("/agents", tags=["agents"])
def agents(request: Request):
    registry = request.app.state.registry
    output = []
    for agent_id in registry.list():
        agent = registry.create(agent_id)
        config = agent.get_config()
        provider, model = registry.dependencies.model_manager.assignment(agent_id)
        output.append({"agent_id": agent_id, "display_name": config.display_name, "purpose": config.purpose, "tools": sorted(config.allowed_tools), "skills": [s.name for s in agent.get_skills()], "provider": provider, "model_id": model})
    return {"agents": output, "plugins": registry.list_plugins()}

