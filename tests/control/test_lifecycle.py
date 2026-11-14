import pytest

from colossus.contracts.core import DomainError
from colossus.control.lifecycle import InstanceLock


def test_second_supervisor_cannot_take_live_state_directory(tmp_path):
    first, second = InstanceLock(tmp_path / "lock"), InstanceLock(tmp_path / "lock")
    first.acquire()
    try:
        with pytest.raises(DomainError, match="already has"):
            second.acquire()
    finally:
        first.release()
    second.acquire()
    second.release()
