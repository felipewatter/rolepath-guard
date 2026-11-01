"""Validated, immutable Kubernetes RBAC primitives."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

class PolicyError(ValueError):
    """Invalid or unsupported RBAC snapshot; analysis must fail closed."""

@dataclass(frozen=True)
class Rule:
    verbs: tuple[str, ...]
    api_groups: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    resource_names: tuple[str, ...] = ()
    non_resource_urls: tuple[str, ...] = ()

@dataclass(frozen=True)
class Role:
    kind: str
    name: str
    namespace: str | None
    rules: tuple[Rule, ...]
    labels: tuple[tuple[str, str], ...] = ()
    selectors: tuple[dict[str, Any], ...] = ()
    aggregation_defined: bool = False

    @property
    def key(self) -> tuple[str, str | None, str]:
        return self.kind, self.namespace, self.name

@dataclass(frozen=True)
class Subject:
    kind: str
    name: str
    namespace: str | None = None

    @property
    def identity(self) -> str:
        if self.kind == 'ServiceAccount':
            return f'ServiceAccount:{self.namespace}:{self.name}'
        return f'{self.kind}:{self.name}'

@dataclass(frozen=True)
class Binding:
    kind: str
    name: str
    namespace: str | None
    role_kind: str
    role_name: str
    subjects: tuple[Subject, ...]

    @property
    def identifier(self) -> str:
        return f'{self.kind}/{self.namespace or "cluster"}/{self.name}'

@dataclass(frozen=True)
class Request:
    principal: str
    verb: str
    resource: str = ''
    api_group: str = ''
    namespace: str | None = None
    resource_name: str | None = None
    non_resource_url: str | None = None
    name_filter: bool = False

    def __post_init__(self) -> None:
        if self.non_resource_url and self.resource:
            raise PolicyError('non_resource_url and resource are mutually exclusive')
        if not self.non_resource_url and not self.resource:
            raise PolicyError('resource or non_resource_url is required')
        if not self.principal.startswith(('User:', 'Group:', 'ServiceAccount:')):
            raise PolicyError('principal must be User:..., Group:..., or ServiceAccount:<namespace>:<name>')
        if self.principal.startswith('ServiceAccount:') and len(self.principal.split(':')) != 3:
            raise PolicyError('service account principal requires namespace and name')
        if self.non_resource_url and not self.non_resource_url.startswith('/'):
            raise PolicyError('non-resource URL must start with /')
        if not self.verb:
            raise PolicyError('verb must not be empty')

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> 'Request':
        if not isinstance(raw, dict):
            raise PolicyError('request must be an object')
        allowed = set(cls.__dataclass_fields__)
        unknown = set(raw) - allowed
        if unknown:
            raise PolicyError(f'unknown request fields: {sorted(unknown)}')
        try:
            return cls(**raw)
        except TypeError as e:
            raise PolicyError(f'invalid request: {e}') from e

@dataclass(frozen=True)
class Evidence:
    binding: str
    role: str
    rule_index: int
    subject: str

    def to_dict(self) -> dict[str, Any]:
        return vars(self)
