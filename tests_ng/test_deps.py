from __future__ import annotations

from netwatch_ng.system import deps


def test_registry_has_no_duplicate_binaries():
    binaries = [d.binary for d in deps.REGISTRY]
    assert len(binaries) == len(set(binaries))


def test_check_all_returns_one_status_per_dependency():
    statuses = deps.check_all()
    assert len(statuses) == len(deps.REGISTRY)


def test_check_all_marks_true_as_installed(monkeypatch):
    # "true" ships on every Linux system this project targets.
    extra = deps.Dependency("true", "always present", "test", True)
    monkeypatch.setattr(deps, "REGISTRY", deps.REGISTRY + [extra])
    statuses = {s.dependency.binary: s for s in deps.check_all()}
    assert statuses["true"].installed is True


def test_check_all_marks_fake_binary_as_missing(monkeypatch):
    extra = deps.Dependency("netwatch-ng-fake-binary-xyz", "test only", "test", False)
    monkeypatch.setattr(deps, "REGISTRY", deps.REGISTRY + [extra])
    statuses = {s.dependency.binary: s for s in deps.check_all()}
    assert statuses["netwatch-ng-fake-binary-xyz"].installed is False


def test_missing_mandatory_only_flags_mandatory_deps(monkeypatch):
    mandatory_missing = deps.Dependency("netwatch-ng-fake-mandatory", "x", "core", True)
    optional_missing = deps.Dependency("netwatch-ng-fake-optional", "x", "core", False)
    monkeypatch.setattr(deps, "REGISTRY", [mandatory_missing, optional_missing])
    missing = deps.missing_mandatory()
    assert mandatory_missing in missing
    assert optional_missing not in missing
