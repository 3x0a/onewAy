import inspect
from dataclasses import dataclass
from typing import ClassVar
from uuid import UUID


class WebsocketMessage:
    type: ClassVar[str]
    _registry: ClassVar[dict[str, type[WebsocketMessage]]] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        mtype = getattr(cls, "type", None)
        if isinstance(mtype, str) and mtype:
            WebsocketMessage._registry[mtype] = cls

    def to_json(self) -> dict[str, object]:
        out: dict[str, object] = {"type": self.type}
        for k, v in vars(self).items():
            if k.startswith("_"):
                continue
            out[k] = str(v) if isinstance(v, UUID) else v
        return out

    @classmethod
    def from_json(cls, data: dict[str, object]) -> WebsocketMessage:
        mtype = data["type"]
        if not isinstance(mtype, str):
            raise ValueError("Invalid message type")

        msg_cls = cls._registry.get(mtype)
        if msg_cls is None:
            raise ValueError(f"Unknown message type: {mtype!r}")

        sig = inspect.signature(msg_cls.__init__)
        allowed = {
            name
            for name in sig.parameters
            if name not in {"self"}
            and sig.parameters[name].kind
            in {
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            }
        }

        kwargs = {k: v for k, v in data.items() if k in allowed}
        # noinspection PyArgumentList
        return msg_cls(**kwargs)


@dataclass(slots=True)
class Error(WebsocketMessage):
    type = "error"
    message: str


@dataclass(slots=True)
class Ping(WebsocketMessage):
    type = "ping"


@dataclass(slots=True)
class Pong(WebsocketMessage):
    type = "pong"


@dataclass(slots=True)
class StartModule(WebsocketMessage):
    type = "start_module"
    module_name: str


@dataclass(slots=True)
class Stdout(WebsocketMessage):
    type = "stdout"
    module_name: str
    data: str
