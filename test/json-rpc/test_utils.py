"""
Utility / address manipulation JSON-RPC method tests for TOS.

Covers:
  - detectAddress
  - detectHash
  - packAddress
  - unpackAddress
"""
import pytest


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

    @pytest.mark.parametrize("address,expected_code", [
        (FRIENDLY_BOUNCEABLE, 200),
        (RAW_LOWER, 200),
        (RAW_UPPER, 200),
        ("not_an_address", 422),
        ("", 422),
    ])
    def test_detect(self, api_method_call, address, expected_code):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == expected_code
        if expected_code == 200:
            data = response.json()
            assert data["ok"] is True

    def test_no_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  2. detectHash
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectHash:

    METHOD = "detectHash"

    @pytest.mark.parametrize("hash_val,expected_code", [
        # standard base64
        ("CPUE4WXeEJT+Dwz1fY/rkreWvYnsOt3I44i1G5ojJPM=", 200),
        # standard base64 without padding -- should fail
        ("CPUE4WXeEJT+Dwz1fY/rkreWvYnsOt3I44i1G5ojJPM", 422),
        # url-safe base64 with padding
        ("CPUE4WXeEJT-Dwz1fY_rkreWvYnsOt3I44i1G5ojJPM=", 200),
        # url-safe base64 without padding
        ("CPUE4WXeEJT-Dwz1fY_rkreWvYnsOt3I44i1G5ojJPM", 200),
        # hex lowercase
        ("08f504e165de1094fe0f0cf57d8feb92b796bd89ec3addc8e388b51b9a2324f3", 200),
        # hex uppercase
        ("08F504E165DE1094FE0F0CF57D8FEB92B796BD89EC3ADDC8E388B51B9A2324F3", 200),
        # garbage
        ("not a hash", 422),
        ("", 422),
    ])
    def test_detect(self, api_method_call, hash_val, expected_code):
        response = api_method_call(self.METHOD, hash=hash_val)
        assert response.status_code == expected_code
        if expected_code == 200:
            data = response.json()
            assert data["ok"] is True

    def test_no_hash(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  3. packAddress
# ═══════════════════════════════════════════════════════════════════════════

class TestPackAddress:

    METHOD = "packAddress"

    @pytest.mark.parametrize("address", ALL_FORMS)
    def test_all_forms(self, api_method_call, address):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        # Result should be one of the two friendly forms
        assert data["result"] in {FRIENDLY_BOUNCEABLE, FRIENDLY_NONBOUNCEABLE}

    def test_no_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  4. unpackAddress
# ═══════════════════════════════════════════════════════════════════════════

class TestUnpackAddress:

    METHOD = "unpackAddress"

    @pytest.mark.parametrize("address", ALL_FORMS)
    def test_all_forms(self, api_method_call, address):
        response = api_method_call(self.METHOD, address=address)
        assert response.status_code == 200, response.json().get("error")
        data = response.json()
        assert data["ok"] is True
        assert data["result"] == EXPECTED_RAW

    def test_no_address(self, api_method_call):
        response = api_method_call(self.METHOD)
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False

    def test_invalid_address(self, api_method_call):
        response = api_method_call(self.METHOD, address="invalid")
        assert response.status_code == 200
        assert response.json()["ok"] is False
        assert response.json()["ok"] is False
