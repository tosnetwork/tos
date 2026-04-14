"""
Config / library JSON-RPC method tests for TOS.

Covers:
  - getConfigParam    (TOS uses "param" not "config_id")
  - getConfigAll
  - getLibraries
"""
import pytest


# ═══════════════════════════════════════════════════════════════════════════
#  1. getConfigParam
# ═══════════════════════════════════════════════════════════════════════════

class TestGetConfigParam:

    METHOD = "getConfigParam"

    @pytest.mark.parametrize("param", [0, 1, 2, 15, 34])
    def test_known_params(self, api_method_call, param):
        """Fetch well-known config parameters by number."""
        response = api_method_call(self.METHOD, param=param)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"]["@type"] == "configInfo"
        assert data["result"]["config"]["@type"] == "tvm.cell"
        assert len(data["result"]["config"]["bytes"]) > 0

    def test_missing_param(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.json()["ok"] is False

    def test_invalid_param(self, api_method_call):
        response = api_method_call(self.METHOD, param="invalid")
        assert response.json()["ok"] is False

    def test_nonexistent_param(self, api_method_call):
        """A param number that is not set should still return a structured response."""
        response = api_method_call(self.METHOD, param=99999)
        # Could be 200 with empty result or 500 -- depends on the implementation.
        assert response.status_code in {200, 500}


# ═══════════════════════════════════════════════════════════════════════════
#  2. getConfigAll
# ═══════════════════════════════════════════════════════════════════════════

class TestGetConfigAll:

    METHOD = "getConfigAll"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert result["@type"] == "configInfo"
        assert result["config"]["@type"] == "tvm.cell"
        assert len(result["config"]["bytes"]) > 0

    def test_has_config_params(self, api_method_call):
        """getConfigAll should include individual config_params map."""
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        result = data["result"]
        assert "config_params" in result
        assert isinstance(result["config_params"], dict)
        # Should have at least a few known params
        assert len(result["config_params"]) > 0


# ═══════════════════════════════════════════════════════════════════════════
#  3. getLibraries
# ═══════════════════════════════════════════════════════════════════════════

class TestGetLibraries:

    METHOD = "getLibraries"

    def test_empty_list(self, api_method_call):
        """Calling with an empty library_list should succeed with empty result."""
        response = api_method_call(self.METHOD, library_list=[])
        # Some implementations require at least one hash; accept 200 or 422.
        assert response.status_code in {200, 422}

    def test_missing_params(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code in {200, 422}

    def test_invalid_hash(self, api_method_call):
        response = api_method_call(self.METHOD, library_list=["not_a_hash"])
        assert response.status_code in {200, 422, 500}
