"""Minimal source-loaded bootstrap fixture for launcher boundary tests."""


def main(arguments: list[str]) -> int:
    if arguments[0] == "explode":
        raise RuntimeError("fixture failure")
    return {"invalid": True, "safe": 23}[arguments[0]]
