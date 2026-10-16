"""
Utility / address manipulation JSON-RPC method tests for TOS.

Covers:
  - detectAddress
  - detectHash
  - packAddress
  - unpackAddress
"""
import pytest

from rpc_contract import assert_success, expect_error, expect_result


# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

# All four representations of the same address
RAW_LOWER = "0:83dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8"
RAW_UPPER = "0:83DFD552E63729B472FCBCC8C45EBCC6691702558B68EC7527E1BA403A0F31A8"
FRIENDLY_BOUNCEABLE = "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N"
FRIENDLY_NONBOUNCEABLE = "UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBI"

ALL_FORMS = [FRIENDLY_BOUNCEABLE, FRIENDLY_NONBOUNCEABLE, RAW_LOWER, RAW_UPPER]

EXPECTED_RAW = RAW_UPPER


# ═══════════════════════════════════════════════════════════════════════════
#  1. detectAddress
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectAddress:

    METHOD = "detectAddress"

    @pytest.mark.parametrize("address,accepted", [
        (FRIENDLY_BOUNCEABLE, True),
        (RAW_LOWER, True),
        (RAW_UPPER, True),
        ("not_an_address", False),
        ("", False),
    ])
    def test_detect(self, api_method_call, address, accepted):
        response = api_method_call(self.METHOD, address=address)
        if accepted:
            expect_result(response)
        else:
            expect_error(response, -32602, "INVALID_ARGUMENT", retryable=False)

    def test_no_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  2. detectHash
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectHash:

    METHOD = "detectHash"

    @pytest.mark.parametrize("hash_val,accepted", [
        # standard base64
        ("CPUE4WXeEJT+Dwz1fY/rkreWvYnsOt3I44i1G5ojJPM=", True),
        # standard base64 without padding -- should fail
        ("CPUE4WXeEJT+Dwz1fY/rkreWvYnsOt3I44i1G5ojJPM", False),
        # url-safe base64 with padding
        ("CPUE4WXeEJT-Dwz1fY_rkreWvYnsOt3I44i1G5ojJPM=", True),
        # url-safe base64 without padding
        ("CPUE4WXeEJT-Dwz1fY_rkreWvYnsOt3I44i1G5ojJPM", True),
        # hex lowercase
        ("08f504e165de1094fe0f0cf57d8feb92b796bd89ec3addc8e388b51b9a2324f3", True),
        # hex uppercase
        ("08F504E165DE1094FE0F0CF57D8FEB92B796BD89EC3ADDC8E388B51B9A2324F3", True),
        # garbage
        ("not a hash", False),
        ("", False),
    ])
    def test_detect(self, api_method_call, hash_val, accepted):
        response = api_method_call(self.METHOD, hash=hash_val)
        if accepted:
            expect_result(response)
        else:
            expect_error(response, -32602, "INVALID_ARGUMENT", retryable=False)

    def test_no_hash(self, api_method_call):
        response = api_method_call(self.METHOD)
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  3. packAddress
# ═══════════════════════════════════════════════════════════════════════════

class TestPackAddress:

    METHOD = "packAddress"

    @pytest.mark.parametrize("address", ALL_FORMS)
    def test_all_forms(self, api_method_call, address):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        # Result should be one of the two friendly forms
        assert data["result"] in {FRIENDLY_BOUNCEABLE, FRIENDLY_NONBOUNCEABLE}

    def test_no_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        expect_error(response)

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        expect_error(response)


# ═══════════════════════════════════════════════════════════════════════════
#  4. unpackAddress
# ═══════════════════════════════════════════════════════════════════════════

class TestUnpackAddress:

    METHOD = "unpackAddress"

    @pytest.mark.parametrize("address", ALL_FORMS)
    def test_all_forms(self, api_method_call, address):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == 200, response.text
        data = response.json()
        assert_success(data)
        assert data["result"] == EXPECTED_RAW

    def test_no_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        expect_error(response)

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        expect_error(response)
