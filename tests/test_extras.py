import ast
import importlib
import pathlib
import sys

import pytest

import jwks_client


PACKAGE_ROOT = pathlib.Path(jwks_client.__file__).parent
INTEGRATION_MODULES = {"litestar.py": "litestar", "fastapi.py": "fastapi"}
CORE_DEPENDENCY_ROOTS = frozenset({"jwks_client", "jwt", "httpware", "httpx2", "cryptography"})


def collect_third_party_imports(path: pathlib.Path) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    return {root for root in roots if root not in sys.stdlib_module_names}


def test_core_modules_import_only_core_dependencies() -> None:
    offenders = {
        path.name: extra
        for path in sorted(PACKAGE_ROOT.glob("*.py"))
        if path.name not in INTEGRATION_MODULES and (extra := collect_third_party_imports(path) - CORE_DEPENDENCY_ROOTS)
    }

    assert offenders == {}


@pytest.mark.parametrize(("module_file", "extra"), INTEGRATION_MODULES.items())
def test_integration_without_its_extra_names_the_extra(
    monkeypatch: pytest.MonkeyPatch, module_file: str, extra: str
) -> None:
    module_name = f"jwks_client.{module_file.removesuffix('.py')}"
    monkeypatch.setitem(sys.modules, extra, None)
    for name in [name for name in sys.modules if name.startswith(f"{extra}.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.delitem(sys.modules, module_name, raising=False)

    with pytest.raises(ImportError, match=rf"pip install 'jwks-client\[{extra}\]'"):
        importlib.import_module(module_name)
