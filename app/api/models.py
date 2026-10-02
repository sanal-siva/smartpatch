"""Versioned wire contracts shared by Smart Patch and the central service."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Component(BaseModel):
    model_config = ConfigDict(extra='allow')
    component_id: str = Field(min_length=1, max_length=256)
    scope: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=256)
    architecture: str = Field(default='', max_length=64)
    source_name: str = Field(default='', max_length=256)
    source_version: str = Field(default='', max_length=256)
    purl: str = Field(default='', max_length=2048)
    distro: dict | str = Field(default_factory=dict)
    image_digest: str = Field(default='', max_length=256)


class SyncEnvelope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal[1] = 1
    device_id: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_.:-]+$')
    hostname: str = Field(default='', max_length=256)
    platform: str = Field(default='', max_length=256)
    sonic_version: str = Field(default='', max_length=256)
    build_id: str = Field(default='', max_length=256)
    epoch: str = Field(min_length=1, max_length=128)
    sequence: int = Field(ge=0)
    kind: Literal['checkpoint', 'delta', 'heartbeat']
    baseline_digest: str = Field(default='', max_length=256)
    inventory_digest: str = Field(min_length=1, max_length=256)
    collected_at: str = Field(min_length=1, max_length=64)
    components: list[Component] = Field(default_factory=list, max_length=100000)
    removed: list[str] = Field(default_factory=list, max_length=100000)
    facts: list[dict[str, Any]] = Field(default_factory=list, max_length=2000)
    resources: dict[str, Any] = Field(default_factory=dict)
    artifact_verified: bool = False
    manifest: dict[str, Any] = Field(default_factory=dict)
    manifest_digest: str = Field(default='',max_length=256)
    clock_alignment: dict[str,Any] = Field(default_factory=dict)

    @field_validator('components')
    @classmethod
    def distinct_components(cls, values):
        ids = [v.component_id for v in values]
        if len(ids) != len(set(ids)):
            raise ValueError('component_id values must be unique within a message')
        return values


class VulnerabilityIn(BaseModel):
    model_config = ConfigDict(extra='allow')
    cve_id: str = Field(min_length=1, max_length=128)
    package_name: str = Field(min_length=1, max_length=256)
    affected_version: str = Field(min_length=1, max_length=256)
    severity: str = 'UNKNOWN'
    cvss_score: float | None = Field(default=None, ge=0, le=10)


class AssessmentRequestIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    vulnerabilities: list[VulnerabilityIn] = Field(min_length=1, max_length=1000)
    sonic_version: str = Field(min_length=1, max_length=256)
    device_context: dict[str, Any] = Field(default_factory=dict)


class TokenRequest(BaseModel):
    description: str = Field(min_length=1, max_length=256)
    role: Literal['admin', 'operator', 'agent'] = 'agent'
    device_id: str | None = Field(default=None, max_length=128)


class RepositorySpec(BaseModel):
    model_config = ConfigDict(extra='forbid')
    base_url: str
    suite: str = Field(min_length=1,max_length=100,pattern=r'^[A-Za-z0-9_.+-]+$')
    components: list[str] = Field(min_length=1,max_length=20)
    architectures: list[str] = Field(min_length=1,max_length=10)
    keyring: str


class ReleaseRequest(BaseModel):
    release_id: str = Field(min_length=1, max_length=256)
    source_url: str = ''
    sbom_source: str = ''
    primary: bool = False
    source_revision: str = ''
    repositories: list[RepositorySpec] = Field(default_factory=list,max_length=8)


class ToolRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


class PlanRequest(BaseModel):
    device_id: str
    finding_ids: list[str] = Field(min_length=1, max_length=100)
    target_version: str | None = None
