"""Shared test configuration for CosmicSec Core tests."""

import os
import sys
import pytest

# Ensure cosmicsec-core is on the Python path
_core_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _core_root not in sys.path:
    sys.path.insert(0, _core_root)


@pytest.fixture(autouse=True)
def _clean_env():
    """Clean up environment variables between tests."""
    keys = [k for k in os.environ if k.startswith("COSMICSEC_")]
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
