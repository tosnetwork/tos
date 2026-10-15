from abc import ABC, abstractmethod
from typing import Any


def is_builtin_class_instance(obj):
    return obj.__class__.__module__ == "__builtins__"


class TlbError(Exception):
    pass


class TlbScheme(ABC):
    """
    abstract class for Tlb Schemes wrappers
    """

    # Schemes expose different serialization APIs (instance and class methods).
    # Only deserialization is a shared class-level operation.

    @classmethod
    @abstractmethod
    def deserialize(cls, *args: Any, **kwargs: Any) -> Any: ...

    def __repr__(self):
        # s = f'< Tl-B {self.__class__.__name__} \n'
        # for k, v in self.__dict__.items():
        #     if isinstance(v, (int, str, float, bytes, bool, dict, tuple, list, NullCell, Address, type(None))):
        #         s += '\t' * t + k + ': ' + v.__repr__() + '\n'
        #     else:
        #         s += '\t' * t + k + ': ' + v.__repr__(t + 1) + '\n'
        # return s + '\t' * t + '>' + '\n'
        return f"< Tl-B {self.__class__.__name__} {' '.join([i + ': ' + j.__repr__() for i, j in self.__dict__.items()])} >"
        # TODO beautiful repr


def require[T](value: T | None) -> T:
    """Require a field of the selected constructor before serializing it."""
    if value is None:
        raise TlbError("required constructor field is absent")
    return value
