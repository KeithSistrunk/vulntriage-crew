"""The mock asset inventory lookup tool.

A scanner tells you what is broken. It has no idea what matters. Business
criticality, internet exposure, and compliance scope come from the CMDB, and that
join is what turns a CVSS score into a risk score.
"""

from __future__ import annotations

from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from ..intel import lookup_asset


class AssetLookupInput(BaseModel):
    host: str = Field(
        ...,
        description="Hostname, FQDN, or IP address, e.g. 'prod-db-01', "
        "'edge-web-01.corp.example.net', or '10.20.4.11'.",
    )


class AssetLookupTool(BaseTool):
    name: str = "lookup_asset"
    description: str = (
        "Look up a host in the asset inventory (CMDB). Returns its role, owning team, OS, "
        "business criticality, whether it is internet-facing, environment, data "
        "classification, compliance scope, and maintenance window. "
        "Use this to judge what a finding on that host is actually worth. Hosts with no "
        "CMDB record come back flagged as unmanaged — which is itself worth reporting."
    )
    args_schema: Type[BaseModel] = AssetLookupInput

    def _run(self, host: str, **_: object) -> str:
        asset = lookup_asset(host)
        if not asset.known_asset:
            return (
                f"{host}: NO CMDB RECORD.\n{asset.notes}\n"
                "Scoring treats it as medium criticality, but an unmanaged host on a "
                "production subnet is a finding in its own right."
            )

        return "\n".join(
            [
                f"{asset.hostname} ({asset.fqdn or 'no FQDN'}) — {asset.role}",
                f"Owner: {asset.owner} | OS: {asset.os}",
                f"Criticality: {asset.criticality} | Environment: {asset.environment} | "
                f"Internet-facing: {asset.internet_facing}",
                f"Data classification: {asset.data_classification} | "
                f"Compliance scope: {', '.join(asset.compliance_scope) or 'none'}",
                f"Maintenance window: {asset.maintenance_window}",
            ]
        )
