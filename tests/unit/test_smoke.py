from __future__ import annotations

import mitm_tracker


def test_package_has_version() -> None:
    assert isinstance(mitm_tracker.__version__, str)
    assert mitm_tracker.__version__
