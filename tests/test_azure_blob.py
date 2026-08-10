"""Azure Blob 测试"""
import pytest

from cain_agent.cloud.azure_blob import BlobCredentialError, BlobExposureChecker


def test_missing_credentials_raises(monkeypatch):
    monkeypatch.delenv("AZURE_STORAGE_CONNECTION_STRING", raising=False)
    with pytest.raises(BlobCredentialError):
        BlobExposureChecker()


def test_credentials_from_param():
    checker = BlobExposureChecker(connection_string="fake")
    assert checker.connection_string == "fake"
