from unittest.mock import patch

from fastapi import HTTPException
import pytest
import main


@pytest.mark.parametrize("classifier,slm,required,expected", [
    (True, True, True, True),
    (True, False, True, False),
    (False, True, True, False),
    (True, False, False, True),
    (False, False, False, False),
])
def test_readiness_requires_all_configured_components(classifier, slm, required, expected):
    state = {"classifier": {"loaded": classifier}, "slm_service": {"loaded": slm}}
    with patch.object(main, "health_check", return_value=state), patch.object(main, "slm_required", return_value=required):
        if expected:
            assert main.readiness_check()["status"] == "ready"
        else:
            with pytest.raises(HTTPException) as error:
                main.readiness_check()
            assert error.value.status_code == 503
