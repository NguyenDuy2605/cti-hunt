import pytest
import os
from cti_hunt.adapters.splunk import SplunkConnection, SplunkError

def test_splunk_rejects_non_local_hosts():
    os.environ["SPLUNK_USER"] = "admin"
    os.environ["SPLUNK_PASS"] = "changeme"
    
    with pytest.raises(ValueError, match="từ chối host: 10.0.0.1"):
        SplunkConnection("10.0.0.1")
        
    with pytest.raises(ValueError, match="từ chối host: splunk.example.com"):
        SplunkConnection("splunk.example.com")
        
    # Should not raise
    SplunkConnection("127.0.0.1")
    SplunkConnection("localhost")

def test_splunk_missing_credentials(monkeypatch):
    monkeypatch.delenv("SPLUNK_USER", raising=False)
    monkeypatch.delenv("SPLUNK_PASS", raising=False)
    with pytest.raises(ValueError, match="Thiếu biến môi trường"):
        SplunkConnection("localhost")

def test_splunk_search_mock(monkeypatch):
    os.environ["SPLUNK_USER"] = "admin"
    os.environ["SPLUNK_PASS"] = "changeme"
    
    conn = SplunkConnection("localhost")
    
    # Mock urlopen
    import io
    class MockResponse:
        def __init__(self, content):
            self.content = content
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def __iter__(self):
            for line in self.content.splitlines():
                yield line.encode('utf-8')
    
    def mock_urlopen(req, *args, **kwargs):
        return MockResponse('{"result": {"event": "test"}}')
        
    monkeypatch.setattr(conn.opener, "open", mock_urlopen)
    
    res = conn.search("index=main")
    assert len(res) == 1
    assert res[0] == {"event": "test"}
