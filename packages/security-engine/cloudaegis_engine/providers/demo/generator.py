"""Deterministic generator for the simulated AWS estate."""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from functools import cached_property
from typing import Any, Callable

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Relationship, Resource

DEMO_REGIONS = ("us-east-1", "us-west-2", "eu-west-1", "ap-south-1")
REGION_WEIGHTS = (0.45, 0.2, 0.2, 0.15)

APPS = ("payments", "checkout", "identity", "analytics", "ledger", "notifications", "search", "catalog",
        "risk-engine", "reporting", "mobile-api", "data-lake", "ml-features", "audit", "billing", "partner-api",
        "inventory", "fulfilment", "support-portal", "marketing-site")
ENVS = ("prod", "prod", "staging", "dev", "shared")
BUCKET_PURPOSES = ("assets", "logs", "backups", "exports", "uploads", "artifacts", "reports", "raw", "curated",
                   "static", "snapshots", "invoices", "media", "terraform-state")
FIRST = ("anika", "rahul", "maria", "james", "wei", "fatima", "lucas", "olivia", "arjun", "sofia", "noah",
         "priya", "liam", "chen", "emma", "diego", "aisha", "kenji", "zara", "omar", "hannah", "ravi")
LAST = ("sharma", "garcia", "smith", "zhang", "khan", "silva", "johnson", "patel", "muller", "rossi",
        "nakamura", "ali", "brown", "iyer", "lopez", "kowalski")
RUNTIMES_OK = ("python3.12", "python3.11", "python3.13", "nodejs20.x", "nodejs22.x", "java21", "provided.al2023")
RUNTIMES_OLD = ("python3.8", "nodejs16.x", "python3.7", "go1.x")
DB_ENGINES = (("postgres", "16.4"), ("mysql", "8.0.39"), ("aurora-postgresql", "15.6"), ("mariadb", "10.11.9"))
INSTANCE_TYPES = ("t3.medium", "t3.large", "m6i.large", "m6i.xlarge", "c6i.2xlarge", "r6i.large", "m7g.large")
EXTERNAL_ACCOUNTS = ("210987654321", "998877665544", "135792468024")

ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
READONLY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
READONLY_DOC = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "ec2:Describe*", "rds:Describe*"], "Resource": "*"}]}


class DemoEstate:
    def __init__(self, account_id: str, seed: int, maturity: float, now: datetime, scale: float = 1.0) -> None:
        self.account_id = account_id
        self.seed = seed
        self.maturity = max(0.0, min(1.0, maturity))
        self.now = now
        self.scale = scale
        self._buckets: list[str] = []
        self._role_arns: dict[str, list[str]] = {"lambda": [], "lambda_admin": []}
        self._sg_by_region: dict[str, list[dict[str, Any]]] = {}

    # -- randomness -----------------------------------------------------------
    def rng(self, *key: Any) -> random.Random:
        return random.Random(f"{self.seed}|" + "|".join(map(str, key)))

    def bad(self, r: random.Random, base_probability: float) -> bool:
        """Draw a fixed value per resource, compare to a maturity-scaled threshold."""
        threshold = base_probability * (1.0 - 0.85 * self.maturity)
        return r.random() < threshold

    def count(self, n: int) -> int:
        return max(1, int(round(n * self.scale)))

    def ago(self, r: random.Random, low: int, high: int) -> str:
        return (self.now - timedelta(days=r.randint(low, high), hours=r.randint(0, 23))).isoformat()

    def region(self, r: random.Random) -> str:
        return r.choices(DEMO_REGIONS, weights=REGION_WEIGHTS)[0]

    def arn(self, service: str, region: str, resource: str) -> str:
        return f"arn:aws:{service}:{region}:{self.account_id}:{resource}"

    def res(self, uid: str, rtype: str, name: str, region: str, props: dict[str, Any],
            tags: dict[str, str] | None = None, rels: list[Relationship] | None = None) -> Resource:
        return Resource(uid=uid, resource_type=rtype, service=rt.SERVICE_OF[rtype], name=name, region=region,
                        account_id=self.account_id, properties=props, tags=tags or {}, relationships=rels or [])

    def _security_groups_for(self, region: str, *preferences: Callable[[dict[str, Any]], bool]
                             ) -> tuple[str, list[dict[str, Any]]]:
        """Security groups for a new resource, keeping resource and group in the same region.

        At small ``scale`` a region may have no suitable group; the resource then
        moves to the first region that has one (deterministic for a given seed).
        """
        for candidate in (region, *DEMO_REGIONS):
            groups = self._sg_by_region.get(candidate, [])
            for prefer in (*preferences, lambda s: True):
                matching = [g for g in groups if prefer(g)]
                if matching:
                    return candidate, matching
        raise RuntimeError("demo estate has no security groups")

    # -- service dispatch ----------------------------------------------------
    def service(self, service: str) -> list[Resource]:
        builders: dict[str, Callable[[], list[Resource]]] = {
            "IAM": lambda: self.iam,
            "S3": lambda: self.s3,
            "EC2": lambda: self.ec2,
            "VPC": lambda: self.vpc,
            "RDS": lambda: self.rds,
            "CloudTrail": lambda: self.cloudtrail,
            "Lambda": lambda: self.lambdas,
            "ECR": lambda: self.ecr,
            "KMS": lambda: self.kms,
            "Secrets Manager": lambda: self.secrets,
        }
        return builders[service]() if service in builders else []

    # -- IAM -------------------------------------------------------------------
    @cached_property
    def iam(self) -> list[Resource]:
        out: list[Resource] = []
        r = self.rng("account")
        weak_policy = self.bad(r, 0.9)
        out.append(self.res(
            f"arn:aws:iam::{self.account_id}:root", rt.AWS_ACCOUNT, f"AWS account {self.account_id}", "global",
            {
                "account_id": self.account_id,
                "root_mfa_enabled": self.maturity >= 0.5,
                "root_access_keys_present": self.maturity < 0.3,
                "password_policy": {
                    "minimum_length": 8 if weak_policy else 14,
                    "require_symbols": True, "require_numbers": True,
                    "require_uppercase": True, "require_lowercase": True,
                    "max_password_age": 90,
                    "password_reuse_prevention": 5 if weak_policy else 24,
                },
                "s3_public_access_block": None if self.maturity < 0.7 else {
                    "block_public_acls": True, "ignore_public_acls": True,
                    "block_public_policy": True, "restrict_public_buckets": True},
            }))

        groups = {
            "Administrators": [{"name": "AdministratorAccess", "arn": ADMIN_ARN}],
            "Developers": [{"name": "PowerUserAccess", "arn": "arn:aws:iam::aws:policy/PowerUserAccess"}],
            "ReadOnly": [{"name": "ReadOnlyAccess", "arn": READONLY_ARN}],
            "DataEngineers": [{"name": "DataEngineerAccess",
                               "arn": f"arn:aws:iam::{self.account_id}:policy/DataEngineerAccess"}],
            "SecurityAudit": [{"name": "SecurityAudit", "arn": "arn:aws:iam::aws:policy/SecurityAudit"}],
            "BillingAdmins": [{"name": "Billing", "arn": "arn:aws:iam::aws:policy/job-function/Billing"}],
            "SRE": [{"name": "SREOperations", "arn": f"arn:aws:iam::{self.account_id}:policy/SREOperations"}],
            "Contractors": [{"name": "ReadOnlyAccess", "arn": READONLY_ARN}],
            "CI": [{"name": "DeploymentPipeline", "arn": f"arn:aws:iam::{self.account_id}:policy/DeploymentPipeline"}],
            "Support": [{"name": "AWSSupportAccess", "arn": "arn:aws:iam::aws:policy/AWSSupportAccess"}],
            "QA": [{"name": "ReadOnlyAccess", "arn": READONLY_ARN}],
            "Finance": [{"name": "Billing", "arn": "arn:aws:iam::aws:policy/job-function/Billing"}],
        }

        def group_docs(group: str) -> list[dict[str, Any]]:
            if group == "Administrators":
                return [{"name": "AdministratorAccess", "source": "group:Administrators", "document": ADMIN_DOC}]
            return [{"name": p["name"], "source": f"group:{group}", "document": READONLY_DOC} for p in groups[group]]

        for gname, attached in groups.items():
            out.append(self.res(
                f"arn:aws:iam::{self.account_id}:group/{gname}", rt.IAM_GROUP, gname, "global",
                {"group_name": gname, "attached_policies": attached, "policy_documents": group_docs(gname),
                 "created_at": self.ago(self.rng("group", gname), 400, 1400)}))

        used_names: set[str] = set()
        for i in range(self.count(84)):
            r = self.rng("user", i)
            human = i < self.count(62)
            if human:
                name = f"{r.choice(FIRST)}.{r.choice(LAST)}"
                if i < 5:
                    group = "Administrators"
                else:
                    group = r.choice(("Developers", "Developers", "ReadOnly", "DataEngineers", "SRE", "SecurityAudit",
                                      "Contractors", "QA", "Support", "Finance"))
            else:
                name = f"svc-{r.choice(APPS)}-{r.choice(('deploy', 'etl', 'sync', 'backup', 'exporter'))}"
                group = "CI"
            name = f"{name}{i}" if i >= 40 or name in used_names else name
            used_names.add(name)
            password = human and not (group == "CI")
            mfa = password and not self.bad(r, 0.55 if group != "Administrators" else 0.6)
            keys = []
            if not human or self.bad(r, 0.45):
                n_keys = 2 if self.bad(r, 0.25) else 1
                for k in range(n_keys):
                    kr = self.rng("key", i, k)
                    stale = self.bad(kr, 0.6)
                    created_days = kr.randint(120, 900) if stale else kr.randint(5, 80)
                    unused = self.bad(kr, 0.35)
                    keys.append({
                        "access_key_id": f"AKIA…{kr.randint(1000, 9999)}",
                        "status": "Active",
                        "created_at": (self.now - timedelta(days=created_days)).isoformat(),
                        "last_used_at": None if unused and kr.random() < 0.3 else (
                            self.ago(kr, 100, 400) if unused else self.ago(kr, 0, 6)),
                    })
            dormant = self.bad(r, 0.3)
            direct_admin = human and i in (6, 7) and self.maturity < 0.75
            attached = [{"name": "AdministratorAccess", "arn": ADMIN_ARN}] if direct_admin else []
            docs = group_docs(group) + ([{"name": "AdministratorAccess", "source": "attached", "document": ADMIN_DOC}]
                                        if direct_admin else [])
            out.append(self.res(
                f"arn:aws:iam::{self.account_id}:user/{name}", rt.IAM_USER, name, "global",
                {
                    "user_name": name,
                    "created_at": self.ago(r, 100, 1500),
                    "password_enabled": password,
                    "password_last_used": (self.ago(r, 95, 400) if dormant else self.ago(r, 0, 20)) if password else None,
                    "mfa_enabled": mfa,
                    "mfa_devices": 1 if mfa else 0,
                    "access_keys": keys,
                    "groups": [group],
                    "attached_policies": attached,
                    "policy_documents": docs,
                },
                tags={"team": r.choice(APPS), "owner": f"{r.choice(FIRST)}@example.com"} if human else {"service": "ci"},
                rels=[Relationship("member_of", f"arn:aws:iam::{self.account_id}:group/{group}")]))

        for i in range(self.count(186)):
            r = self.rng("role", i)
            app = r.choice(APPS)
            kind = r.choices(("lambda", "ec2", "ecs", "cross", "sso", "public"), weights=(55, 15, 12, 8, 9, 1))[0]
            if kind == "public" and not self.bad(r, 1.0):
                kind = "cross"
            name = {
                "lambda": f"{app}-lambda-exec-{i}",
                "ec2": f"{app}-ec2-instance-{i}",
                "ecs": f"{app}-ecs-task-{i}",
                "cross": f"{app}-partner-access-{i}",
                "sso": f"AWSReservedSSO_{r.choice(('Admin', 'Developer', 'ReadOnly'))}_{r.randint(10**7, 10**8)}",
                "public": f"{app}-integration-{i}",
            }[kind]
            service_principal = {"lambda": "lambda.amazonaws.com", "ec2": "ec2.amazonaws.com",
                                 "ecs": "ecs-tasks.amazonaws.com"}.get(kind)
            if service_principal:
                trust = {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}]}
            elif kind == "cross":
                stmt: dict[str, Any] = {"Effect": "Allow",
                                        "Principal": {"AWS": f"arn:aws:iam::{r.choice(EXTERNAL_ACCOUNTS)}:root"},
                                        "Action": "sts:AssumeRole"}
                if not self.bad(r, 0.6):
                    stmt["Condition"] = {"StringEquals": {"sts:ExternalId": f"ext-{r.randint(10**6, 10**7)}"}}
                trust = {"Version": "2012-10-17", "Statement": [stmt]}
            elif kind == "sso":
                trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
                    "Federated": f"arn:aws:iam::{self.account_id}:saml-provider/AWSSSO"},
                    "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"]}]}
            else:
                trust = {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
            admin = kind in ("lambda", "ec2") and self.bad(r, 0.12)
            docs = [{"name": f"{app}-access", "source": "inline", "document": {
                "Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
                     "Resource": f"arn:aws:s3:::prod-{app}-*/*"},
                    {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}]}}]
            if admin:
                docs.append({"name": "AdministratorAccess", "source": "attached", "document": ADMIN_DOC})
            arn = f"arn:aws:iam::{self.account_id}:role/{name}"
            if kind == "lambda":
                self._role_arns["lambda_admin" if admin else "lambda"].append(arn)
            out.append(self.res(arn, rt.IAM_ROLE, name, "global", {
                "role_name": name, "path": "/", "created_at": self.ago(r, 30, 1200),
                "is_service_linked": False, "trust_policy": trust,
                "last_used_at": self.ago(r, 0, 30),
                "attached_policies": [{"name": "AdministratorAccess", "arn": ADMIN_ARN}] if admin else [],
                "policy_documents": docs,
            }, tags={"app": app}))

        policy_names: set[str] = set()
        for i in range(self.count(38)):
            r = self.rng("policy", i)
            app = APPS[i % len(APPS)]
            name = ("DataEngineerAccess", "SREOperations", "DeploymentPipeline")[i] if i < 3 else f"{app}-{r.choice(('service', 'operator', 'pipeline', 'readwrite'))}-policy"
            if name in policy_names:
                name = f"{name}-{i}"
            policy_names.add(name)
            statements: list[dict[str, Any]] = [
                {"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"],
                 "Resource": f"arn:aws:dynamodb:*:{self.account_id}:table/{app}-*"}]
            if self.bad(r, 0.18):
                statements = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            elif self.bad(r, 0.25):
                statements.append({"Effect": "Allow",
                                   "Action": r.choice((["iam:PassRole", "lambda:CreateFunction"],
                                                       ["iam:CreatePolicyVersion"], ["iam:AttachRolePolicy"],
                                                       ["iam:*"])),
                                   "Resource": "*"})
            out.append(self.res(f"arn:aws:iam::{self.account_id}:policy/{name}", rt.IAM_POLICY, name, "global", {
                "policy_name": name, "attachment_count": 0 if r.random() < 0.12 else r.randint(1, 9),
                "default_version": f"v{r.randint(1, 6)}",
                "document": {"Version": "2012-10-17", "Statement": statements},
                "created_at": self.ago(r, 60, 1300),
            }))
        return out

    # -- S3 ------------------------------------------------------------------
    @cached_property
    def s3(self) -> list[Resource]:
        out: list[Resource] = []
        special = ["shared-cloudtrail-logs", "prod-payments-backups", "marketing-site-static-assets",
                   "prod-data-lake-raw", "shared-s3-access-logs"]
        names: list[str] = list(special)
        i = 0
        while len(names) < self.count(183):
            r = self.rng("bucket-name", i)
            name = f"{r.choice(ENVS)}-{r.choice(APPS)}-{r.choice(BUCKET_PURPOSES)}"
            if name not in names:
                names.append(name)
            i += 1
        self._buckets = names
        for idx, name in enumerate(names):
            r = self.rng("bucket", name)
            region = "us-east-1" if idx < 3 else self.region(r)
            prod = name.startswith("prod")
            bpa_off = self.bad(r, 0.25)
            public_policy = (name == "marketing-site-static-assets" and self.maturity < 0.9) or (
                name == "prod-payments-backups" and self.maturity < 0.45) or self.bad(r, 0.03)
            public_acl = (name == "prod-data-lake-raw" and self.maturity < 0.6) or self.bad(r, 0.025)
            if public_policy or public_acl:
                bpa_off = True
            bpa = None if bpa_off else {"block_public_acls": True, "ignore_public_acls": True,
                                        "block_public_policy": True, "restrict_public_buckets": True}
            statements: list[dict[str, Any]] = []
            if public_policy:
                statements.append({"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
                                   "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{name}/*"})
            if name == "shared-cloudtrail-logs":
                statements.append({"Sid": "AWSCloudTrailWrite", "Effect": "Allow",
                                   "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject",
                                   "Resource": f"arn:aws:s3:::{name}/AWSLogs/{self.account_id}/*",
                                   "Condition": {"StringEquals": {"aws:SourceAccount": self.account_id}}})
            if not self.bad(r, 0.4):
                statements.append({"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*",
                                   "Action": "s3:*", "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
                                   "Condition": {"Bool": {"aws:SecureTransport": "false"}}})
            policy = {"Version": "2012-10-17", "Statement": statements} if statements else None
            grants = [{"grantee_type": "CanonicalUser", "grantee_uri": None, "permission": "FULL_CONTROL"}]
            if public_acl:
                grants.append({"grantee_type": "Group", "grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                               "permission": "READ"})
            encrypted = not self.bad(r, 0.12)
            out.append(self.res(f"arn:aws:s3:::{name}", rt.S3_BUCKET, name, region, {
                "bucket_name": name,
                "created_at": self.ago(r, 30, 2000),
                "public_access_block": bpa,
                "policy": policy,
                "policy_is_public": bool(public_policy),
                "acl_grants": grants,
                "encryption": ({"algorithm": "aws:kms" if prod else "AES256",
                                "kms_key_id": f"arn:aws:kms:{region}:{self.account_id}:key/demo-{idx}" if prod else None}
                               if encrypted else None),
                "versioning": "Enabled" if not self.bad(r, 0.35 if not prod else 0.2) else r.choice(("Suspended", "Disabled")),
                "mfa_delete": False,
                "logging_enabled": name not in ("shared-s3-access-logs",) and not self.bad(r, 0.35),
                "logging_target": "shared-s3-access-logs",
                "object_ownership": "ObjectWriter" if public_acl else "BucketOwnerEnforced",
            }, tags={"env": name.split("-")[0], "app": name.split("-")[1] if "-" in name else "shared",
                     "data-classification": r.choice(("internal", "confidential", "public", "restricted"))}))
        return out

    # -- EC2 -----------------------------------------------------------------
    @cached_property
    def _security_groups(self) -> dict[str, list[dict[str, Any]]]:
        vpcs = self._vpc_layout
        sg_total = self.count(110)
        for i in range(sg_total):
            r = self.rng("sg", i)
            vpc = vpcs[i % len(vpcs)]
            region = vpc["region"]
            is_default = i < len(vpcs)
            app = r.choice(APPS)
            gid = f"sg-0{r.getrandbits(56):014x}"
            ingress: list[dict[str, Any]] = []
            egress = [{"protocol": "-1", "from_port": None, "to_port": None, "cidrs": ["0.0.0.0/0"], "ipv6_cidrs": [],
                       "source_groups": []}] if self.bad(r, 0.45) else [
                {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidrs": ["0.0.0.0/0"], "ipv6_cidrs": [],
                 "source_groups": []}]
            if is_default:
                if not self.bad(r, 0.7):
                    egress = []
                else:
                    ingress = [{"protocol": "-1", "from_port": None, "to_port": None, "cidrs": [], "ipv6_cidrs": [],
                                "source_groups": [gid]}]
                purpose = "default"
            else:
                purpose = r.choice(("web", "web", "app", "app", "db", "bastion", "internal", "cache", "batch"))
                if purpose == "web":
                    ingress = [{"protocol": "tcp", "from_port": p, "to_port": p, "cidrs": ["0.0.0.0/0"],
                                "ipv6_cidrs": ["::/0"], "source_groups": []} for p in (80, 443)]
                elif purpose == "bastion":
                    src = ["0.0.0.0/0"] if self.bad(r, 0.85) else ["203.0.113.0/24"]
                    port = 3389 if r.random() < 0.3 else 22
                    ingress = [{"protocol": "tcp", "from_port": port, "to_port": port, "cidrs": src, "ipv6_cidrs": [],
                                "source_groups": []}]
                elif purpose in ("db", "cache"):
                    port = 5432 if purpose == "db" else 6379
                    src = ["0.0.0.0/0"] if self.bad(r, 0.15) else ["10.0.0.0/8"]
                    ingress = [{"protocol": "tcp", "from_port": port, "to_port": port, "cidrs": src, "ipv6_cidrs": [],
                                "source_groups": []}]
                else:
                    ingress = [{"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidrs": ["10.0.0.0/8"],
                                "ipv6_cidrs": [], "source_groups": []}]
                    if self.bad(r, 0.06):
                        ingress.append({"protocol": "-1", "from_port": None, "to_port": None, "cidrs": ["0.0.0.0/0"],
                                        "ipv6_cidrs": [], "source_groups": []})
                    elif self.bad(r, 0.08):
                        ingress.append({"protocol": "tcp", "from_port": 8000, "to_port": 9999, "cidrs": ["0.0.0.0/0"],
                                        "ipv6_cidrs": [], "source_groups": []})
                    if self.bad(r, 0.08):
                        ingress.append({"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"],
                                        "ipv6_cidrs": [], "source_groups": []})
            name = "default" if is_default else f"{app}-{purpose}-sg"
            sg = {"group_id": gid, "group_name": name, "vpc_id": vpc["vpc_id"], "is_default": is_default,
                  "description": f"{purpose} tier for {app}", "ingress": ingress, "egress": egress,
                  "attached_eni_count": 0, "purpose": purpose, "region": region}
            self._sg_by_region.setdefault(region, []).append(sg)
        return self._sg_by_region

    @cached_property
    def ec2(self) -> list[Resource]:
        out: list[Resource] = []
        vpcs = self._vpc_layout
        _ = self._security_groups
        instances: list[Resource] = []
        for i in range(self.count(142)):
            r = self.rng("instance", i)
            region = self.region(r)
            region, region_sgs = self._security_groups_for(region, lambda s: not s["is_default"])
            sg = r.choice(region_sgs)
            sg["attached_eni_count"] += 1
            app = sg["description"].split(" for ")[-1]
            public = sg["purpose"] in ("web", "bastion") or self.bad(r, 0.08)
            iid = f"i-0{r.getrandbits(60):015x}"
            vpc = next((v for v in vpcs if v["region"] == region), vpcs[0])
            subnet_id = vpc["subnets"][r.randrange(len(vpc["subnets"]))]
            state = "stopped" if r.random() < 0.08 else "running"
            instances.append(self.res(self.arn("ec2", region, f"instance/{iid}"), rt.EC2_INSTANCE,
                                      f"{app}-{sg['purpose']}-{i:03d}", region, {
                "instance_id": iid, "instance_type": r.choice(INSTANCE_TYPES), "state": state,
                "launch_time": self.ago(r, 1, 600),
                "public_ip": f"{r.choice((3, 18, 34, 52, 54))}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}" if public else None,
                "private_ip": f"10.{r.randint(0, 31)}.{r.randint(0, 255)}.{r.randint(4, 254)}",
                "vpc_id": vpc["vpc_id"], "subnet_id": subnet_id, "security_group_ids": [sg["group_id"]],
                "imds_http_tokens": "optional" if self.bad(r, 0.4) else "required", "imds_http_endpoint": "enabled",
                "iam_instance_profile": f"arn:aws:iam::{self.account_id}:instance-profile/{app}-ec2",
                "platform": "Windows" if sg["purpose"] == "bastion" and r.random() < 0.3 else "Linux/UNIX",
                "image_id": f"ami-0{r.getrandbits(56):014x}",
            }, tags={"Name": f"{app}-{sg['purpose']}-{i:03d}", "app": app, "env": r.choice(ENVS)}, rels=[
                Relationship("protected_by", self.arn("ec2", region, f"security-group/{sg['group_id']}")),
                Relationship("in_subnet", self.arn("ec2", region, f"subnet/{subnet_id}")),
            ]))
        out.extend(instances)
        _ = self._rds_plan  # databases attach to (and may modify) security groups

        for region, sgs in self._sg_by_region.items():
            for sg in sgs:
                out.append(self.res(self.arn("ec2", region, f"security-group/{sg['group_id']}"),
                                    rt.EC2_SECURITY_GROUP, f"{sg['group_name']} ({sg['group_id']})", region,
                                    {k: v for k, v in sg.items() if k not in ("purpose", "region")},
                                    rels=[Relationship("in_vpc", self.arn("ec2", region, f"vpc/{sg['vpc_id']}"))]))

        for i in range(self.count(170)):
            r = self.rng("volume", i)
            inst = instances[i % len(instances)] if r.random() < 0.9 else None
            region = inst.region if inst else self.region(r)
            vid = f"vol-0{r.getrandbits(60):015x}"
            out.append(self.res(self.arn("ec2", region, f"volume/{vid}"), rt.EC2_VOLUME,
                                f"{inst.name}-data" if inst else vid, region, {
                "volume_id": vid, "encrypted": not self.bad(r, 0.3), "kms_key_id": None,
                "size_gb": r.choice((8, 20, 30, 50, 100, 200, 500)), "volume_type": r.choice(("gp3", "gp3", "io2", "st1")),
                "state": "in-use" if inst else "available",
                "attached_instance_ids": [inst.prop("instance_id")] if inst else [],
            }, rels=[Relationship("attached_to", inst.uid)] if inst else []))

        for region in DEMO_REGIONS:
            r = self.rng("ebs-default", region)
            out.append(self.res(self.arn("ec2", region, "region-settings"), rt.EC2_REGION_SETTINGS,
                                f"EC2 settings ({region})", region,
                                {"ebs_encryption_by_default": not self.bad(r, 0.8)}))
        return out

    # -- VPC -----------------------------------------------------------------
    @cached_property
    def _vpc_layout(self) -> list[dict[str, Any]]:
        layout = []
        for i in range(self.count(8)):
            r = self.rng("vpc", i)
            region = DEMO_REGIONS[i % len(DEMO_REGIONS)]
            layout.append({
                "region": region,
                "vpc_id": f"vpc-0{r.getrandbits(56):014x}",
                "name": "default" if i < len(DEMO_REGIONS) else f"{r.choice(('prod', 'staging', 'shared'))}-core-vpc",
                "is_default": i < len(DEMO_REGIONS),
                "cidr": f"10.{i * 8}.0.0/16" if i >= len(DEMO_REGIONS) else "172.31.0.0/16",
                "subnets": [f"subnet-0{self.rng('subnet', i, s).getrandbits(56):014x}" for s in range(6)],
            })
        return layout

    @cached_property
    def vpc(self) -> list[Resource]:
        out: list[Resource] = []
        for i, v in enumerate(self._vpc_layout):
            r = self.rng("vpc-props", i)
            region = v["region"]
            out.append(self.res(self.arn("ec2", region, f"vpc/{v['vpc_id']}"), rt.VPC, v["name"], region, {
                "vpc_id": v["vpc_id"], "cidr_block": v["cidr"], "is_default": v["is_default"],
                "flow_logs_enabled": not self.bad(r, 0.95 if v["is_default"] else 0.6),
            }, tags={"Name": v["name"]}))
            igw = f"igw-0{r.getrandbits(56):014x}"
            out.append(self.res(self.arn("ec2", region, f"internet-gateway/{igw}"), rt.VPC_INTERNET_GATEWAY,
                                f"{v['name']}-igw", region, {"igw_id": igw, "attached_vpc_ids": [v["vpc_id"]]},
                                rels=[Relationship("attached_to", self.arn("ec2", region, f"vpc/{v['vpc_id']}"))]))
            if not v["is_default"] or i < 6:
                nat = f"nat-0{r.getrandbits(64):016x}"
                out.append(self.res(self.arn("ec2", region, f"natgateway/{nat}"), rt.VPC_NAT_GATEWAY,
                                    f"{v['name']}-nat", region, {"nat_id": nat, "vpc_id": v["vpc_id"],
                                                                 "subnet_id": v["subnets"][0], "state": "available",
                                                                 "public_ip": f"52.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"}))
            public_rt = f"rtb-0{r.getrandbits(56):014x}"
            private_rt = f"rtb-0{r.getrandbits(56):014x}"
            public_subnets, private_subnets = v["subnets"][:2], v["subnets"][2:]
            out.append(self.res(self.arn("ec2", region, f"route-table/{public_rt}"), rt.VPC_ROUTE_TABLE,
                                f"{v['name']}-public-rt", region, {
                "route_table_id": public_rt, "vpc_id": v["vpc_id"], "is_main": v["is_default"],
                "routes": [{"destination": v["cidr"], "target": "local"}, {"destination": "0.0.0.0/0", "target": igw}],
                "subnet_ids": public_subnets, "routes_to_internet_gateway": True}))
            out.append(self.res(self.arn("ec2", region, f"route-table/{private_rt}"), rt.VPC_ROUTE_TABLE,
                                f"{v['name']}-private-rt", region, {
                "route_table_id": private_rt, "vpc_id": v["vpc_id"], "is_main": False,
                "routes": [{"destination": v["cidr"], "target": "local"}, {"destination": "0.0.0.0/0", "target": "nat"}],
                "subnet_ids": private_subnets, "routes_to_internet_gateway": False}))
            for s, sid in enumerate(v["subnets"]):
                sr = self.rng("subnet-props", i, s)
                public = sid in public_subnets
                out.append(self.res(self.arn("ec2", region, f"subnet/{sid}"), rt.VPC_SUBNET,
                                    f"{v['name']}-{'public' if public else 'private'}-{s}", region, {
                    "subnet_id": sid, "vpc_id": v["vpc_id"], "cidr_block": f"10.{i * 8}.{s * 16}.0/20",
                    "availability_zone": f"{region}{'abc'[s % 3]}",
                    "map_public_ip_on_launch": v["is_default"] or (public and self.bad(sr, 0.7)) or self.bad(sr, 0.05),
                    "has_internet_route": public or v["is_default"],
                }, rels=[Relationship("in_vpc", self.arn("ec2", region, f"vpc/{v['vpc_id']}"))]))
            acl = f"acl-0{r.getrandbits(56):014x}"
            allow_admin = self.bad(r, 0.9)
            entries = [
                {"rule_number": 100, "egress": False, "protocol": "-1", "action": "allow", "cidr": "0.0.0.0/0",
                 "from_port": None, "to_port": None},
                {"rule_number": 32767, "egress": False, "protocol": "-1", "action": "deny", "cidr": "0.0.0.0/0",
                 "from_port": None, "to_port": None},
                {"rule_number": 100, "egress": True, "protocol": "-1", "action": "allow", "cidr": "0.0.0.0/0",
                 "from_port": None, "to_port": None},
            ]
            if not allow_admin:
                entries[:0] = [
                    {"rule_number": 10, "egress": False, "protocol": "6", "action": "deny", "cidr": "0.0.0.0/0",
                     "from_port": 22, "to_port": 22},
                    {"rule_number": 20, "egress": False, "protocol": "6", "action": "deny", "cidr": "0.0.0.0/0",
                     "from_port": 3389, "to_port": 3389},
                ]
            out.append(self.res(self.arn("ec2", region, f"network-acl/{acl}"), rt.VPC_NETWORK_ACL,
                                f"{v['name']}-nacl", region, {"nacl_id": acl, "vpc_id": v["vpc_id"], "is_default": True,
                                                              "entries": entries, "subnet_ids": v["subnets"]}))
        return out

    # -- RDS -----------------------------------------------------------------
    @cached_property
    def _rds_plan(self) -> list[Resource]:
        _ = self._security_groups
        out: list[Resource] = []
        for i in range(self.count(74)):
            r = self.rng("rds", i)
            region = self.region(r)
            app = r.choice(APPS)
            env = r.choice(ENVS)
            engine, version = r.choice(DB_ENGINES)
            name = f"{env}-{app}-db-{i:02d}"
            region, sgs = self._security_groups_for(
                region, lambda s: s["purpose"] in ("db", "cache"), lambda s: not s["is_default"])
            sg = r.choice(sgs)
            sg["attached_eni_count"] += 1
            public = (i == 3 and self.maturity < 0.65) or self.bad(r, 0.08)
            out.append(self.res(self.arn("rds", region, f"db:{name}"), rt.RDS_INSTANCE, name, region, {
                "db_instance_id": name, "engine": engine, "engine_version": version,
                "instance_class": r.choice(("db.t4g.medium", "db.r6g.large", "db.m6g.xlarge", "db.r6g.2xlarge")),
                "status": "available", "publicly_accessible": public,
                "storage_encrypted": not self.bad(r, 0.2 if env == "prod" else 0.4),
                "kms_key_id": None, "backup_retention_period": 0 if self.bad(r, 0.15) else r.choice((7, 14, 35)),
                "log_exports": [] if self.bad(r, 0.55) else (["postgresql"] if "postgres" in engine else ["error", "audit"]),
                "security_group_ids": [sg["group_id"]],
                "deletion_protection": not self.bad(r, 0.4 if env == "prod" else 0.7),
                "multi_az": env == "prod",
                "endpoint": f"{name}.c{r.getrandbits(40):010x}.{region}.rds.amazonaws.com:{5432 if 'postgres' in engine else 3306}",
                "created_at": self.ago(r, 40, 1500),
            }, tags={"app": app, "env": env}, rels=[
                Relationship("protected_by", self.arn("ec2", region, f"security-group/{sg['group_id']}"))]))
            if public and i == 3:
                # Make the flagship public database also reachable from the internet.
                sg["ingress"] = sg["ingress"] + [{"protocol": "tcp", "from_port": 5432, "to_port": 5432,
                                                  "cidrs": ["0.0.0.0/0"], "ipv6_cidrs": [], "source_groups": []}]
        return out

    @cached_property
    def rds(self) -> list[Resource]:
        _ = self.ec2
        return self._rds_plan

    # -- CloudTrail ----------------------------------------------------------
    @cached_property
    def cloudtrail(self) -> list[Resource]:
        r = self.rng("trail")
        trails = [
            ("organization-trail", "us-east-1", True, self.maturity >= 0.15, True, "shared-cloudtrail-logs", True, True),
            ("legacy-audit-trail", "us-east-1", False, False, False, "shared-cloudtrail-logs", False, False),
            ("ap-south-1-dev-trail", "ap-south-1", False, True, self.maturity >= 0.8, "shared-cloudtrail-logs", False, False),
        ]
        out = []
        for name, region, multi, logging, validation, bucket, kms, cw in trails:
            out.append(self.res(self.arn("cloudtrail", region, f"trail/{name}"), rt.CLOUDTRAIL_TRAIL, name, region, {
                "trail_name": name, "home_region": region, "is_multi_region": multi, "is_organization_trail": False,
                "is_logging": logging, "log_file_validation": validation, "s3_bucket_name": bucket,
                "kms_key_id": f"arn:aws:kms:us-east-1:{self.account_id}:key/{r.getrandbits(64):016x}" if kms and self.maturity > 0.4 else None,
                "cloudwatch_log_group_arn": f"arn:aws:logs:{region}:{self.account_id}:log-group:cloudtrail:*" if cw else None,
                "include_global_events": multi,
            }, rels=[Relationship("logs_to", f"arn:aws:s3:::{bucket}")]))
        return out

    # -- Lambda --------------------------------------------------------------
    @cached_property
    def lambdas(self) -> list[Resource]:
        _ = self.iam
        out: list[Resource] = []
        env_sets = (["LOG_LEVEL", "TABLE_NAME"], ["LOG_LEVEL", "QUEUE_URL", "REGION"],
                    ["DB_HOST", "DB_USER", "DB_PASSWORD"], ["STRIPE_API_KEY", "LOG_LEVEL"],
                    ["BUCKET", "PREFIX"], [], ["SLACK_WEBHOOK_TOKEN", "CHANNEL"], ["FEATURE_FLAGS"])
        for i in range(self.count(392)):
            r = self.rng("lambda", i)
            region = self.region(r)
            app = r.choice(APPS)
            name = f"{app}-{r.choice(('handler', 'worker', 'processor', 'webhook', 'cron', 'authorizer', 'etl', 'notifier'))}-{i:03d}"
            admin_roles, roles = self._role_arns["lambda_admin"], self._role_arns["lambda"]
            role = r.choice(admin_roles) if admin_roles and self.bad(r, 0.06) else (r.choice(roles) if roles else None)
            env = list(env_sets[r.randrange(len(env_sets))])
            if not self.bad(r, 0.35):
                env = [e for e in env if e not in ("DB_PASSWORD", "STRIPE_API_KEY", "SLACK_WEBHOOK_TOKEN")]
            url = None
            if r.random() < 0.08:
                url = "NONE" if self.bad(r, 0.7) else "AWS_IAM"
            policy = None
            if r.random() < 0.15:
                stmt: dict[str, Any] = {"Sid": "AllowInvoke", "Effect": "Allow",
                                        "Principal": {"Service": "apigateway.amazonaws.com"},
                                        "Action": "lambda:InvokeFunction", "Resource": self.arn("lambda", region, f"function:{name}")}
                if self.bad(r, 0.3):
                    stmt["Principal"] = "*"
                else:
                    stmt["Condition"] = {"ArnLike": {"AWS:SourceArn": self.arn("execute-api", region, "abc123/*")}}
                policy = {"Version": "2012-10-17", "Statement": [stmt]}
            runtime = r.choice(RUNTIMES_OLD) if self.bad(r, 0.12) else r.choice(RUNTIMES_OK)
            out.append(self.res(self.arn("lambda", region, f"function:{name}"), rt.LAMBDA_FUNCTION, name, region, {
                "function_name": name, "runtime": runtime, "package_type": "Zip", "role_arn": role,
                "function_url_auth_type": url, "resource_policy": policy, "environment_variable_names": env,
                "kms_key_arn": self.arn("kms", region, f"key/{r.getrandbits(64):016x}") if env and not self.bad(r, 0.35) else None,
                "last_modified": self.ago(r, 1, 500), "vpc_id": None,
            }, tags={"app": app}, rels=[Relationship("executes_as", role)] if role else []))
        return out

    # -- ECR -----------------------------------------------------------------
    @cached_property
    def ecr(self) -> list[Resource]:
        out = []
        for i in range(self.count(40)):
            r = self.rng("ecr", i)
            region = self.region(r)
            name = f"{APPS[i % len(APPS)]}/{r.choice(('api', 'worker', 'frontend', 'migrations'))}"
            public = self.bad(r, 0.05)
            out.append(self.res(self.arn("ecr", region, f"repository/{name}"), rt.ECR_REPOSITORY, name, region, {
                "repository_name": name, "repository_uri": f"{self.account_id}.dkr.ecr.{region}.amazonaws.com/{name}",
                "scan_on_push": not self.bad(r, 0.55), "image_tag_mutability": "MUTABLE" if self.bad(r, 0.7) else "IMMUTABLE",
                "encryption_type": "AES256", "kms_key": None,
                "repository_policy": {"Version": "2012-10-17", "Statement": [{"Sid": "Pull", "Effect": "Allow",
                                      "Principal": "*", "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]}]}
                if public else None,
                "created_at": self.ago(r, 30, 900),
            }))
        return out

    # -- KMS -----------------------------------------------------------------
    @cached_property
    def kms(self) -> list[Resource]:
        out = []
        for i in range(self.count(60)):
            r = self.rng("kms", i)
            region = self.region(r)
            customer = i < self.count(42)
            key_id = f"{r.getrandbits(32):08x}-{r.getrandbits(16):04x}-{r.getrandbits(16):04x}-{r.getrandbits(16):04x}-{r.getrandbits(48):012x}"
            spec = "SYMMETRIC_DEFAULT" if r.random() < 0.9 else "RSA_2048"
            pending = customer and self.bad(r, 0.05)
            statements: list[dict[str, Any]] = [{"Sid": "EnableRootPermissions", "Effect": "Allow",
                                                 "Principal": {"AWS": f"arn:aws:iam::{self.account_id}:root"},
                                                 "Action": "kms:*", "Resource": "*"}]
            if customer and i == 5 and self.maturity < 0.5:
                statements.append({"Sid": "AllowUse", "Effect": "Allow", "Principal": {"AWS": "*"},
                                   "Action": ["kms:Decrypt", "kms:DescribeKey"], "Resource": "*"})
            app = APPS[i % len(APPS)]
            out.append(self.res(self.arn("kms", region, f"key/{key_id}"), rt.KMS_KEY,
                                f"alias/{app}-{r.choice(('data', 'backups', 'logs', 'secrets'))}" if customer else f"alias/aws/{r.choice(('s3', 'ebs', 'rds', 'lambda'))}",
                                region, {
                "key_id": key_id, "key_manager": "CUSTOMER" if customer else "AWS",
                "key_state": "PendingDeletion" if pending else "Enabled", "key_spec": spec,
                "key_usage": "ENCRYPT_DECRYPT" if spec == "SYMMETRIC_DEFAULT" else "SIGN_VERIFY",
                "rotation_enabled": (not self.bad(r, 0.5)) if customer else True,
                "policy": {"Version": "2012-10-17", "Statement": statements} if customer else None,
                "description": f"{app} encryption key" if customer else "Default key managed by AWS",
                "deletion_date": (self.now + timedelta(days=r.randint(3, 25))).isoformat() if pending else None,
                "created_at": self.ago(r, 60, 1500),
            }))
        return out

    # -- Secrets Manager -----------------------------------------------------
    @cached_property
    def secrets(self) -> list[Resource]:
        out = []
        for i in range(self.count(85)):
            r = self.rng("secret", i)
            region = self.region(r)
            name = f"{r.choice(ENVS)}/{r.choice(APPS)}/{r.choice(('db-credentials', 'api-key', 'oauth-client', 'webhook-secret', 'service-token'))}-{i}"
            # Draw every random value in a fixed order so that maturity only flips
            # outcomes and never shifts the stream (stable ARNs across scans).
            rotation = not self.bad(r, 0.5)
            stale = self.bad(r, 0.25) and rotation
            suffix = r.getrandbits(24)
            rotated_old, rotated_recent = self.ago(r, 100, 300), self.ago(r, 1, 29)
            changed, created = self.ago(r, 1, 300), self.ago(r, 120, 1200)
            cmk = r.random() >= 0.5
            key_id = r.getrandbits(64)
            policy = None
            if i == 11 and self.maturity < 0.55:
                policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                                                                  "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
            out.append(self.res(self.arn("secretsmanager", region, f"secret:{name}-{suffix:06x}"), rt.SECRET,
                                name, region, {
                "secret_name": name, "rotation_enabled": rotation, "rotation_days": 30 if rotation else None,
                "last_rotated_at": (rotated_old if stale else rotated_recent) if rotation else None,
                "last_changed_at": changed, "created_at": created,
                "kms_key_id": self.arn("kms", region, f"key/{key_id:016x}") if cmk else None,
                "resource_policy": policy,
            }))
        return out
