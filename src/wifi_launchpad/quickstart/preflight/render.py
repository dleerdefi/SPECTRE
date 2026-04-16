"""Serialization helpers for preflight results."""


def serialize_preflight(checker, all_passed):
    """Serialize preflight results for API/CLI consumers."""

    return {
        "all_passed": all_passed,
        "summary": checker.get_summary(),
        "checks": [
            {
                "name": result.name,
                "passed": result.passed,
                "message": result.message,
                "fix_command": result.fix_command,
                "fix_description": result.fix_description,
            }
            for result in checker.results
        ],
        "adapters": [
            {
                "interface": adapter.interface,
                "mac": adapter.mac,
                "driver": adapter.driver,
                "chipset": adapter.chipset,
                "usb_id": adapter.usb_id,
                "monitor_capable": adapter.monitor_capable,
                "injection_capable": adapter.injection_capable,
                "recommended_role": adapter.recommended_role,
            }
            for adapter in checker.adapters
        ],
        "fixes_available": [
            {
                "name": result.name,
                "message": result.message,
                "fix_command": result.fix_command,
                "fix_description": result.fix_description,
            }
            for result in checker.fixes_available
        ],
    }
