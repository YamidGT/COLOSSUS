"""Owned integration fixture; real HTTP/database adapters remain separate."""

from Policy import default__ as policy
import _dafny


def identity(value):
    if type(value) is not str:
        raise ValueError("Identity must be a canonical string")
    return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, value))


def change_password(authenticated, actor, target, password, users):
    if type(authenticated) is not bool:
        raise ValueError("Authentication state must be Boolean")
    decision = policy.MayChangePassword(authenticated, identity(actor), identity(target), target in users)
    if not decision:
        raise PermissionError("Password change denied")
    users[target]["password"] = password


def read_secret(authenticated, actor, book):
    if type(authenticated) is not bool:
        raise ValueError("Authentication state must be Boolean")
    owner = book["owner"] if book is not None else ""
    decision = policy.MayReadBookSecret(authenticated, identity(actor), identity(owner), book is not None)
    if not decision:
        raise PermissionError("Secret read denied")
    return book["secret"]


def register(username, email, password, requested_admin):
    if type(requested_admin) is not bool:
        raise ValueError("Role request must be Boolean")
    return {"username": username, "email": email, "password": password,
            "admin": policy.RegistrationRole(requested_admin)}


def public_user(user):
    result = policy.PublicUserProjection(identity(user["username"]), identity(user["email"]),
                                        identity(user["password"]), user["admin"])
    return {"username": "".join(result.username), "email": "".join(result.email)}
