"""
Config / library JSON-RPC method tests for TOS.

Covers:
  - getConfigParam    (TOS uses "param" not "config_id")
  - getConfigAll
  - getLibraries
"""

import pytest
from rpc_contract import assert_success, expect_error, expect_invalid_param, expect_result


@pytest.fixture(scope="module")
def absent_config_param(api_method_call_get):
    """The smallest config id the running chain does not set."""
    result = expect_result(api_method_call_get("getConfigAll"))
    present = {int(k) for k in result["config_params"]}
    absent = next(i for i in range(0, 256) if i not in present)
    return absent


# ═══════════════════════════════════════════════════════════════════════════
#  1. getConfigParam
# ═══════════════════════════════════════════════════════════════════════════


class TestGetConfigParam:
    METHOD = "getConfigParam"

    @pytest.mark.parametrize("param", [0, 1, 2, 15, 34])
    def test_known_params(self, api_method_call, param):
        """Fetch well-known config parameters by number."""
        response = api_method_call(self.METHOD, param=param)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"]["@type"] == "configInfo"
        assert data["result"]["config"]["@type"] == "tvm.cell"
        assert len(data["result"]["config"]["bytes"]) > 0

    def test_missing_param(self, api_method_call):
        response = api_method_call(self.METHOD)
        expect_error(response, -32602, "INVALID_ARGUMENT", retryable=False)

    def test_invalid_param(self, api_method_call):
        response = api_method_call(self.METHOD, param="invalid")
        expect_error(response, -32602, "INVALID_ARGUMENT", retryable=False)

    def test_nonexistent_param(self, api_method_call):
        """An id that is not set is a definite, non-retryable absence."""
        response = api_method_call(self.METHOD, param=99999)
        error = expect_error(response, -32004, "CONFIG_PARAM_ABSENT", retryable=False)
        assert error["message"] == "config param 99999 not found"

    def test_absent_param_from_config(self, api_method_call, absent_config_param):
        """A small id missing from this chain's config answers CONFIG_PARAM_ABSENT."""
        response = api_method_call(self.METHOD, param=absent_config_param)
        error = expect_error(response, -32004, "CONFIG_PARAM_ABSENT", retryable=False)
        assert error["message"] == f"config param {absent_config_param} not found"

    def test_absent_param_decoded_view(
        self, api_method_call_no_get, api_method_call_get, absent_config_param
    ):
        response = api_method_call_no_get(
            self.METHOD, param=absent_config_param, include_decoded=True
        )
        expect_error(response, -32004, "CONFIG_PARAM_ABSENT", retryable=False)
        # GET turns the literal text "true" into the boolean.
        response = api_method_call_get(
            self.METHOD, param=absent_config_param, include_decoded="true"
        )
        expect_error(response, -32004, "CONFIG_PARAM_ABSENT", retryable=False)

    @pytest.mark.parametrize("seqno", ["abc", -1, 1.5])
    def test_invalid_seqno(self, api_method_call, seqno):
        response = api_method_call(self.METHOD, param=0, seqno=seqno)
        expect_invalid_param(response, "seqno")


# ═══════════════════════════════════════════════════════════════════════════
#  2. getConfigAll
# ═══════════════════════════════════════════════════════════════════════════


class TestGetConfigAll:
    METHOD = "getConfigAll"

    def test_basic(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        result = data["result"]
        assert result["@type"] == "configInfo"
        assert result["config"]["@type"] == "tvm.cell"
        assert len(result["config"]["bytes"]) > 0

    def test_has_config_params(self, api_method_call):
        """getConfigAll should include individual config_params map."""
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        data = response.json()
        assert_success(data)
        result = data["result"]
        assert "config_params" in result
        assert isinstance(result["config_params"], dict)
        # Should have at least a few known params
        assert len(result["config_params"]) > 0

    @pytest.mark.parametrize("seqno", ["abc", -1, 1.5])
    def test_invalid_seqno(self, api_method_call, seqno):
        response = api_method_call(self.METHOD, seqno=seqno)
        expect_invalid_param(response, "seqno")

    def test_seqno_as_string_is_refused(self, api_method_call_no_get, last_mc_seqno):
        response = api_method_call_no_get(self.METHOD, seqno=str(last_mc_seqno))
        expect_invalid_param(response, "seqno")

    def test_pinned_seqno(self, api_method_call, last_mc_seqno):
        result = expect_result(api_method_call(self.METHOD, seqno=last_mc_seqno))
        assert result["@type"] == "configInfo"


# ═══════════════════════════════════════════════════════════════════════════
#  3. getLibraries
# ═══════════════════════════════════════════════════════════════════════════


class TestGetLibraries:
    METHOD = "getLibraries"

    @staticmethod
    def _result_or_error(response):
        assert response.status_code == 200, response.text
        body = response.json()
        if "error" in body:
            return expect_error(response)
        return assert_success(body)

    def test_empty_list(self, api_method_call):
        """An empty library_list either succeeds or is a structured refusal."""
        self._result_or_error(api_method_call(self.METHOD, library_list=[]))

    def test_missing_params(self, api_method_call):
        self._result_or_error(api_method_call(self.METHOD))

    def test_invalid_hash(self, api_method_call):
        self._result_or_error(api_method_call(self.METHOD, library_list=["not_a_hash"]))
