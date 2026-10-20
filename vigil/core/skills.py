from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Skill:
    name: str
    purpose: str
    procedure: tuple[str, ...]

    def render(self) -> str:
        return f"{self.name}: {self.purpose}\n" + "\n".join(f"- {step}" for step in self.procedure)

