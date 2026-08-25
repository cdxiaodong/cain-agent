"""Cloud provider read-only exposure modules.

Each sub-module wraps a vendor SDK in a read-only, fully-mockable checker that
produces structured findings. No write/delete operations are implemented or
registered as agent tools.
"""

from cain_agent.cloud import aliyun_oss, aws_s3, docker_image, k8s_rbac

__all__ = [
    "aliyun_oss",
    "aws_s3",
    "docker_image",
    "k8s_rbac",
]
