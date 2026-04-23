"""Verify v3.1.0 public API surface is reachable from the top-level package."""


def test_top_level_imports():
    """Downstream consumers (robot-md) should use `from rcan import X`."""
    from rcan import (
        build_eu_register_entry,
        build_ifu,
        build_incident_report,
        build_safety_benchmark,
        canonical_json,
        sign_body,
        verify_body,
    )

    assert callable(canonical_json)
    assert callable(sign_body)
    assert callable(verify_body)
    assert callable(build_safety_benchmark)
    assert callable(build_ifu)
    assert callable(build_incident_report)
    assert callable(build_eu_register_entry)


def test_explicit_module_imports_still_work():
    """Explicit paths remain supported for consumers who want origin clarity."""
    from rcan.compliance import (
        build_eu_register_entry,
        build_ifu,
        build_incident_report,
        build_safety_benchmark,
    )
    from rcan.encoding import canonical_json
    from rcan.hybrid import sign_body, verify_body

    assert all(
        callable(x)
        for x in (
            canonical_json, sign_body, verify_body,
            build_safety_benchmark, build_ifu,
            build_incident_report, build_eu_register_entry,
        )
    )
