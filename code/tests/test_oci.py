from unauthorized_channels.isolation import IsolationPolicy
from unauthorized_channels.oci import (
    bind_mount,
    build_oci_config,
    oci_linux_namespaces,
    spec_has_forbidden_mounts,
)


def test_network_none_adds_network_namespace() -> None:
    types = {n["type"] for n in oci_linux_namespaces(IsolationPolicy(network="none"))}
    assert "network" in types
    assert "cgroup" not in types
    assert "pid" in types


def test_bridge_policy_does_not_add_network_namespace() -> None:
    types = {n["type"] for n in oci_linux_namespaces(IsolationPolicy(network="bridge"))}
    assert "network" not in types
    assert "pid" in types


def test_default_policy_is_airgapped() -> None:
    assert IsolationPolicy().network == "none"


def test_spec_rejects_credential_env() -> None:
    try:
        build_oci_config(args=["true"], env={"OPENAI_API_KEY": "x"})
    except ValueError as exc:
        assert "credential" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_spec_forbids_docker_sock_mount() -> None:
    spec = build_oci_config(
        args=["true"],
        mounts=[bind_mount("/tmp/ws", "/workspace"), bind_mount("/var/run/docker.sock", "/var/run/docker.sock")],
    )
    bad = spec_has_forbidden_mounts(spec)
    assert bad


def test_clean_spec_has_no_forbidden_mounts() -> None:
    spec = build_oci_config(
        args=["true"],
        mounts=[bind_mount("/tmp/ws", "/workspace"), bind_mount("/tmp/cc", "/ccache")],
    )
    assert spec_has_forbidden_mounts(spec) == []
    assert spec["process"]["noNewPrivileges"] is True
    assert spec["process"]["capabilities"]["effective"] == []
