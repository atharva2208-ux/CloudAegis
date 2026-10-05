"""EC2 discovery: instances, security groups, network interfaces, EBS volumes, region settings."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Relationship, Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import call, iso, name_from_tags, tags_to_dict


def normalize_permissions(perms: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out = []
    for perm in perms or []:
        out.append({
            "protocol": str(perm.get("IpProtocol", "-1")),
            "from_port": perm.get("FromPort"),
            "to_port": perm.get("ToPort"),
            "cidrs": [r["CidrIp"] for r in perm.get("IpRanges", []) if "CidrIp" in r],
            "ipv6_cidrs": [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if "CidrIpv6" in r],
            "source_groups": [g.get("GroupId") for g in perm.get("UserIdGroupPairs", []) if g.get("GroupId")],
        })
    return out


def _paginate(client: Any, op: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    for region in ctx.regions:
        ec2 = ctx.client("ec2", region)

        enis = _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces")
        sg_usage: Counter[str] = Counter()
        for eni in enis:
            for group in eni.get("Groups", []):
                sg_usage[group["GroupId"]] += 1
            tags = tags_to_dict(eni.get("TagSet"))
            yield Resource(
                uid=ctx.arn("ec2", region, f"network-interface/{eni['NetworkInterfaceId']}"),
                resource_type=rt.EC2_NETWORK_INTERFACE,
                service="EC2",
                name=name_from_tags(tags, eni["NetworkInterfaceId"]),
                region=region,
                account_id=ctx.account_id,
                tags=tags,
                properties={
                    "eni_id": eni["NetworkInterfaceId"],
                    "interface_type": eni.get("InterfaceType"),
                    "subnet_id": eni.get("SubnetId"),
                    "vpc_id": eni.get("VpcId"),
                    "private_ip": eni.get("PrivateIpAddress"),
                    "public_ip": (eni.get("Association") or {}).get("PublicIp"),
                    "attached_instance_id": (eni.get("Attachment") or {}).get("InstanceId"),
                    "security_group_ids": [g["GroupId"] for g in eni.get("Groups", [])],
                },
            )

        for sg in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
            tags = tags_to_dict(sg.get("Tags"))
            yield Resource(
                uid=ctx.arn("ec2", region, f"security-group/{sg['GroupId']}"),
                resource_type=rt.EC2_SECURITY_GROUP,
                service="EC2",
                name=f"{sg.get('GroupName')} ({sg['GroupId']})",
                region=region,
                account_id=ctx.account_id,
                tags=tags,
                properties={
                    "group_id": sg["GroupId"],
                    "group_name": sg.get("GroupName"),
                    "description": sg.get("Description"),
                    "vpc_id": sg.get("VpcId"),
                    "is_default": sg.get("GroupName") == "default",
                    "ingress": normalize_permissions(sg.get("IpPermissions")),
                    "egress": normalize_permissions(sg.get("IpPermissionsEgress")),
                    "attached_eni_count": sg_usage.get(sg["GroupId"], 0),
                },
                relationships=[Relationship("in_vpc", ctx.arn("ec2", region, f"vpc/{sg['VpcId']}"))] if sg.get("VpcId") else [],
            )

        for reservation in _paginate(ec2, "describe_instances", "Reservations"):
            for inst in reservation.get("Instances", []):
                iid = inst["InstanceId"]
                tags = tags_to_dict(inst.get("Tags"))
                metadata = inst.get("MetadataOptions", {})
                sgs = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
                rels = [Relationship("protected_by", ctx.arn("ec2", region, f"security-group/{g}")) for g in sgs]
                if inst.get("SubnetId"):
                    rels.append(Relationship("in_subnet", ctx.arn("ec2", region, f"subnet/{inst['SubnetId']}")))
                profile = (inst.get("IamInstanceProfile") or {}).get("Arn")
                yield Resource(
                    uid=ctx.arn("ec2", region, f"instance/{iid}"),
                    resource_type=rt.EC2_INSTANCE,
                    service="EC2",
                    name=name_from_tags(tags, iid),
                    region=region,
                    account_id=ctx.account_id,
                    tags=tags,
                    properties={
                        "instance_id": iid,
                        "instance_type": inst.get("InstanceType"),
                        "state": (inst.get("State") or {}).get("Name"),
                        "launch_time": iso(inst.get("LaunchTime")),
                        "public_ip": inst.get("PublicIpAddress"),
                        "private_ip": inst.get("PrivateIpAddress"),
                        "vpc_id": inst.get("VpcId"),
                        "subnet_id": inst.get("SubnetId"),
                        "security_group_ids": sgs,
                        "imds_http_tokens": metadata.get("HttpTokens", "optional"),
                        "imds_http_endpoint": metadata.get("HttpEndpoint", "enabled"),
                        "iam_instance_profile": profile,
                        "platform": inst.get("PlatformDetails") or inst.get("Platform") or "Linux/UNIX",
                        "image_id": inst.get("ImageId"),
                    },
                    relationships=rels,
                )

        for vol in _paginate(ec2, "describe_volumes", "Volumes"):
            tags = tags_to_dict(vol.get("Tags"))
            attached = [a["InstanceId"] for a in vol.get("Attachments", []) if a.get("InstanceId")]
            yield Resource(
                uid=ctx.arn("ec2", region, f"volume/{vol['VolumeId']}"),
                resource_type=rt.EC2_VOLUME,
                service="EC2",
                name=name_from_tags(tags, vol["VolumeId"]),
                region=region,
                account_id=ctx.account_id,
                tags=tags,
                properties={
                    "volume_id": vol["VolumeId"],
                    "encrypted": bool(vol.get("Encrypted")),
                    "kms_key_id": vol.get("KmsKeyId"),
                    "size_gb": vol.get("Size"),
                    "volume_type": vol.get("VolumeType"),
                    "state": vol.get("State"),
                    "attached_instance_ids": attached,
                },
                relationships=[Relationship("attached_to", ctx.arn("ec2", region, f"instance/{i}")) for i in attached],
            )

        default_enc = call(ec2.get_ebs_encryption_by_default, default={}).get("EbsEncryptionByDefault", False)
        yield Resource(
            uid=ctx.arn("ec2", region, "region-settings"),
            resource_type=rt.EC2_REGION_SETTINGS,
            service="EC2",
            name=f"EC2 settings ({region})",
            region=region,
            account_id=ctx.account_id,
            properties={"ebs_encryption_by_default": bool(default_enc)},
        )
