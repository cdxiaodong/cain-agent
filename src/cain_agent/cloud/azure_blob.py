"""Azure Blob Storage 暴露检测模块（只读）"""
from dataclasses import dataclass


@dataclass
class BlobFinding:
    """Azure Blob 发现"""
    cloud: str = "azure"
    service: str = "blob"
    resource: str = ""
    issue_type: str = ""
    severity: str = "medium"
    detail: str = ""


class BlobCredentialError(Exception):
    """凭证错误"""
    pass


class BlobExposureChecker:
    """Azure Blob Storage 暴露检测器"""
    
    def __init__(self, connection_string: str | None = None):
        """初始化检测器"""
        import os
        self.connection_string = connection_string or os.getenv("AZURE_STORAGE_CONNECTION_STRING")
        if not self.connection_string:
            raise BlobCredentialError("缺少凭证：AZURE_STORAGE_CONNECTION_STRING")
    
    def check_public_containers(self) -> list[BlobFinding]:
        """检测公开容器（mock 实现）"""
        return []
