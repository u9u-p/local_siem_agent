from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


@runtime_checkable
class LLMClient(Protocol):
    def generate_structured(self, prompt: str, schema: type[T]) -> T: ...
    def health_check(self) -> bool: ...
    def model_available(self) -> bool: ...
    # A method rather than an attribute, matching the rest of this Protocol and
    # keeping isinstance() checks against it well-defined.
    def model_name(self) -> str: ...
