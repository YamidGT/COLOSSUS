"""Independent positive/negative checks over a packaged generated component."""

import copy
import itertools
import json
import sys

sys.path.insert(0, "/app/policy-py")
sys.path.insert(0, "/app")
from policy_wrapper import change_password, read_secret, register, public_user

checks = 0
for authenticated, actor, target in itertools.product([False, True], ["", "alice", "bob"], ["alice", "bob", "missing"]):
    users = {"alice": {"password": "old-a"}, "bob": {"password": "old-b"}}
    before = copy.deepcopy(users)
    expected = authenticated and actor == target and target in users
    try:
        change_password(authenticated, actor, target, "new-password", users)
    except PermissionError:
        assert not expected and users == before
    else:
        assert expected
        assert users[target]["password"] == "new-password"
        assert users["bob" if target == "alice" else "alice"] == before["bob" if target == "alice" else "alice"]
    checks += 1
for authenticated, actor, book in itertools.product([False, True], ["", "alice", "bob"], [None, {"owner": "alice", "secret": "private"}]):
    expected = authenticated and book is not None and actor == book["owner"]
    try:
        value = read_secret(authenticated, actor, book)
    except PermissionError:
        assert not expected
    else:
        assert expected and value == "private"
    checks += 1
for role in [False, True]:
    user = register("alice", "alice@example.invalid", "private", role)
    assert user["admin"] is False
    assert public_user(user) == {"username": "alice", "email": "alice@example.invalid"}
    assert public_user(user | {"password": "other-private", "admin": True}) == public_user(user)
    checks += 3
for authenticated, actor in [("false", "alice"), (True, None), (True, 1)]:
    users = {"alice": {"password": "original"}}
    try:
        change_password(authenticated, actor, "alice", "changed", users)
    except ValueError:
        pass
    else:
        raise AssertionError("Malformed adapter input accepted")
    assert users["alice"]["password"] == "original"
    checks += 1
print(json.dumps({"checks": checks, "result": "pass", "scope": "owned compiled-policy wrapper fixture"}))
