"""GCP GCS 暴露检测测试（全 mock，零触网）"""
import os
import pytest
from cain_agent.cloud.gcp_gcs import GcsExposureChecker, GcsCredentialError, GcsFinding


def test_missing_credentials_raises():
    """缺凭证报错"""
    os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
    with pytest.raises(GcsCredentialError, match="缺少凭证"):
        GcsExposureChecker()


def test_credentials_from_env(monkeypatch):
    """从环境变量读取凭证"""
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/fake/path.json")
    checker = GcsExposureChecker()
    assert checker.service_account_json == "/fake/path.json"


def test_credentials_from_param():
    """从参数读取凭证"""
    checker = GcsExposureChecker(service_account_json="/fake/path.json", project_id="test-project")
    assert checker.service_account_json == "/fake/path.json"
    assert checker.project_id == "test-project"


def test_check_public_buckets_empty(monkeypatch):
    """无公开桶返回空列表"""
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/fake/path.json")
    checker = GcsExposureChecker()
    findings = checker.check_public_buckets()
    assert findings == []


def test_check_public_buckets_with_public(monkeypatch):
    """检测到公开桶"""
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/fake/path.json")
    checker = GcsExposureChecker()
    
    # Mock 方法
    checker._list_buckets = lambda: ["public-bucket", "private-bucket"]
    checker._is_bucket_public = lambda b: b == "public-bucket"
    checker._check_sensitive_files = lambda b: []
    
    findings = checker.check_public_buckets()
    assert len(findings) == 1
    assert findings[0].cloud == "gcp"
    assert findings[0].service == "gcs"
    assert findings[0].resource == "public-bucket"
    assert findings[0].issue_type == "public-bucket"
    assert findings[0].severity == "high"


def test_check_sensitive_files(monkeypatch):
    """检测敏感文件"""
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/fake/path.json")
    checker = GcsExposureChecker()
    
    checker._list_buckets = lambda: ["test-bucket"]
    checker._is_bucket_public = lambda b: True
    checker._check_sensitive_files = lambda b: [".env", "credentials.json"]
    
    findings = checker.check_public_buckets()
    assert len(findings) == 2  # public-bucket + sensitive-files
    
    sensitive_finding = [f for f in findings if f.issue_type == "sensitive-files"][0]
    assert sensitive_finding.severity == "critical"
    assert ".env" in sensitive_finding.detail


def test_gcs_finding_format():
    """GcsFinding 格式对齐"""
    finding = GcsFinding(
        resource="test-bucket",
        issue_type="public-bucket",
        severity="high",
        detail="测试发现"
    )
    assert finding.cloud == "gcp"
    assert finding.service == "gcs"
