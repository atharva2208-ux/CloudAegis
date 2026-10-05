"""Lambda function discovery.

Environment variable *values* are never read into CloudAegis — only
variable names are retained, for the secrets-in-environment heuristic.
"""

from __future__ import annotations

from typing import Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Relationship, Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import call, policy_doc
from cloudaegis_engine.providers.aws.collectors.ec2 import _paginate


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    for region in ctx.regions:
        lam = ctx.client("lambda", region)
        for fn in _paginate(lam, "list_functions", "Functions"):
            name = fn["FunctionName"]
            url_cfg = call(lam.get_function_url_config, FunctionName=name, missing=("ResourceNotFoundException",))
            policy = call(lam.get_policy, FunctionName=name, missing=("ResourceNotFoundException",))
            env_names = sorted(((fn.get("Environment") or {}).get("Variables") or {}).keys())
            role = fn.get("Role")
            yield Resource(
                uid=fn["FunctionArn"],
                resource_type=rt.LAMBDA_FUNCTION,
                service="Lambda",
                name=name,
                region=region,
                account_id=ctx.account_id,
                properties={
                    "function_name": name,
                    "runtime": fn.get("Runtime"),
                    "package_type": fn.get("PackageType", "Zip"),
                    "role_arn": role,
                    "function_url_auth_type": url_cfg.get("AuthType") if url_cfg else None,
                    "resource_policy": policy_doc(policy.get("Policy")) if policy else None,
                    "environment_variable_names": env_names,
                    "kms_key_arn": fn.get("KMSKeyArn"),
                    "last_modified": fn.get("LastModified"),
                    "vpc_id": (fn.get("VpcConfig") or {}).get("VpcId") or None,
                },
                relationships=[Relationship("executes_as", role)] if role else [],
            )
