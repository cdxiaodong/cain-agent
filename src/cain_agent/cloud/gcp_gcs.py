"""GCP Cloud Storage 暴露检测模块（只读）"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class GcsFinding:
    """GCS 存储桶发现"""
    cloud: str = "gcp"
    service: str = "gcs"
    resource: str = ""
    issue_type: str = ""
    severity: str = "medium"
    detail: str = ""


class GcsCredentialError(Exception):
    """凭证错误"""
    pass


class GcsExposureChecker:
    """GCP Cloud Storage 暴露检测器"""
    
    def __init__(
        self,
        service_account_json: Optional[str] = None,
        project_id: Optional[str] = None
    ):
        """初始化检测器
        
        Args:
            service_account_json: 服务账号 JSON 路径（或从 GOOGLE_APPLICATION_CREDENTIALS 读取）
            project_id: GCP 项目 ID
        """
        self.service_account_json = service_account_json
        self.project_id = project_id
        self._validate_credentials()
    
    def _validate_credentials(self):
        """验证凭证"""
        import os
        if not self.service_account_json:
            self.service_account_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if not self.service_account_json:
            raise GcsCredentialError(
                "缺少凭证：请提供 service_account_json 或设置 GOOGLE_APPLICATION_CREDENTIALS 环境变量"
            )
    
    def check_public_buckets(self) -> list[GcsFinding]:
        """检测公开存储桶
        
        Returns:
            GcsFinding 列表
        """
        findings = []
        buckets = self._list_buckets()
        
        for bucket in buckets:
            if self._is_bucket_public(bucket):
                findings.append(GcsFinding(
                    resource=bucket,
                    issue_type="public-bucket",
                    severity="high",
                    detail=f"存储桶 {bucket} 允许公开访问（allUsers/allAuthenticatedUsers）"
                ))
                
                sensitive_files = self._check_sensitive_files(bucket)
                if sensitive_files:
                    findings.append(GcsFinding(
                        resource=bucket,
                        issue_type="sensitive-files",
                        severity="critical",
                        detail=f"公开桶中发现敏感文件: {', '.join(sensitive_files)}"
                    ))
        
        return findings
    
    def _list_buckets(self) -> list[str]:
        """列出所有存储桶（mock 实现）"""
        # 实际实现使用 google.cloud.storage.Client.list_buckets()
        return []
    
    def _is_bucket_public(self, bucket_name: str) -> bool:
        """检查存储桶是否公开（mock 实现）"""
        # 实际实现使用 bucket.get_iam_policy() 检查 allUsers/allAuthenticatedUsers
        return False
    
    def _check_sensitive_files(self, bucket_name: str) -> list[str]:
        """检测敏感文件（mock 实现）"""
        sensitive_patterns = [".env", ".key", ".pem", "credentials", "secret"]
        # 实际实现使用 bucket.list_blobs() 遍历文件
        return []
