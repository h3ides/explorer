from __future__ import annotations

"""
Read-only authorization probing for EVM smart accounts.

This module intentionally uses eth_call only.

It is designed to answer questions such as:

    Can caller B reach upgradeTo()?
    Does caller B hit UnauthorizedCaller?
    Does the call reach a later UUPS validation check?
    Does a caller-specific RPC failure create an evidence gap?

No state-changing transaction is broadcast by this module.
"""

from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable

from .rpc.eth import EthRpc, RpcResult


# ---------------------------------------------------------------------------
# Known actors
# ---------------------------------------------------------------------------

OWNER = "0xe147c5f96ff6fd753384a995cc2c7bab96bcbdf6"
ATTACKER = "0x68af0efa38a801821116dfa95642eddafd07df35"
ENTRY_POINT = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"


# ---------------------------------------------------------------------------
# Function selectors
# ---------------------------------------------------------------------------

SELECTORS: dict[str, str] = {
    "execute": "0xb61d27f6",
    "executeBatch": "0x47e1da2a",
    "installPlugin": "0x6c6b4d3e",
    "transferNativeOwnership": "0x13af4035",
    "upgradeTo": "0x3659cfe6",
    "upgradeToAndCall": "0x4f1ef286",
    "validateUserOp": "0xe9ae5c53",
}


# ERC-1967 implementation currently observed for the target.
DEFAULT_CANDIDATE_IMPLEMENTATION = (
    "0xd206ac7fef53d83ed4563e770b28dba90d0d9ec8"
)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class AuthorizationProbeResult:
    proxy: str
    function: str
    selector: str
    caller: str
    caller_role: str
    mode: str

    status: str
    rpc_status: str

    revert_data: str | None = None
    error: str | None = None

    candidate_implementation: str | None = None

    evidence: dict[str, Any] | None = None

    @property
    def is_evidence_gap(self) -> bool:
        return self.status == "evidence_gap"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def _word(value: str) -> str:
    """
    Encode an address or uint256 as one ABI word.

    This helper intentionally handles only values needed by the probes.
    """
    value = _strip_0x(value)

    if len(value) > 64:
        raise ValueError(f"ABI value is longer than one word: {value}")

    return value.lower().rjust(64, "0")


def encode_address(address: str) -> str:
    if not address.startswith("0x") or len(address) != 42:
        raise ValueError(f"Invalid EVM address: {address}")

    return _word(address)


def encode_uint256(value: int) -> str:
    if value < 0:
        raise ValueError("uint256 cannot be negative")

    return hex(value)[2:].rjust(64, "0")


def encode_bytes(data: bytes) -> str:
    """
    ABI encode a dynamic bytes value.

    Layout:

        offset
        length
        data padded to 32 bytes
    """
    encoded = data.hex()
    padded_length = ((len(encoded) + 63) // 64) * 64

    return (
        encode_uint256(32)
        + encode_uint256(len(data))
        + encoded.ljust(padded_length, "0")
    )


def selector(function: str) -> str:
    try:
        return SELECTORS[function]
    except KeyError as exc:
        raise ValueError(f"Unsupported function: {function}") from exc


# ---------------------------------------------------------------------------
# Calldata builders
# ---------------------------------------------------------------------------


def calldata_upgrade_to(new_implementation: str) -> str:
    return selector("upgradeTo") + encode_address(new_implementation)


def calldata_upgrade_to_and_call(
    new_implementation: str,
    data: bytes = b"",
) -> str:
    """
    ABI:

        upgradeToAndCall(address,bytes)
    """
    return (
        selector("upgradeToAndCall")
        + encode_address(new_implementation)
        + encode_bytes(data)
    )


def calldata_execute(
    target: str,
    value: int = 0,
    data: bytes = b"",
) -> str:
    """
    ABI:

        execute(address,uint256,bytes)
    """
    return (
        selector("execute")
        + encode_address(target)
        + encode_uint256(value)
        + encode_bytes(data)
    )


def calldata_transfer_native_ownership(
    new_owner: str,
) -> str:
    return selector("transferNativeOwnership") + encode_address(new_owner)


# ---------------------------------------------------------------------------
# Revert decoding
# ---------------------------------------------------------------------------


# UnauthorizedCaller() has selector 0x... only if computed from its signature.
# Keep known selector values configurable because deployed versions may differ.
UNAUTHORIZED_CALLER_SELECTORS = {
    # Common custom-error selector for Circle BaseMSCA UnauthorizedCaller().
    # The probe does not rely solely on this value; it also records raw revert
    # data and attempts textual classification where possible.
}


def classify_revert(revert_data: str | None) -> str:
    """
    Classify a revert conservatively.

    IMPORTANT:
        Unknown revert != authorization failure.

    A revert can occur after authorization, e.g. during UUPS compatibility
    checking.
    """
    if not revert_data:
        return "reverted_without_data"

    normalized = revert_data.lower()

    if normalized[:10] in UNAUTHORIZED_CALLER_SELECTORS:
        return "unauthorized_revert"

    # Solidity Error(string):
    #
    #   0x08c379a0
    #
    # We don't attempt to fully decode arbitrary ABI strings here. Raw revert
    # data is preserved in the evidence record.
    if normalized.startswith("0x08c379a0"):
        return "reverted_with_error_string"

    # Solidity Panic(uint256):
    #
    #   0x4e487b71
    #
    if normalized.startswith("0x4e487b71"):
        return "panic"

    return "reverted_other"


# ---------------------------------------------------------------------------
# RPC result normalization
# ---------------------------------------------------------------------------


def _rpc_result_value(result: RpcResult) -> Any:
    """
    Extract the value from the existing RpcResult without assuming too much
    about its exact implementation.

    The existing project uses RpcResult as the return type of EthRpc methods.
    This helper supports common dataclass/object/dict representations.
    """
    if isinstance(result, dict):
        return result.get("result")

    if hasattr(result, "result"):
        return getattr(result, "result")

    if hasattr(result, "value"):
        return getattr(result, "value")

    return None


def _rpc_result_error(result: RpcResult) -> Any:
    if isinstance(result, dict):
        return result.get("error")

    if hasattr(result, "error"):
        return getattr(result, "error")

    return None


# ---------------------------------------------------------------------------
# Authorization probe
# ---------------------------------------------------------------------------


class AuthorizationProbe:
    """
    Execute read-only authorization probes against a proxy.

    Every probe becomes an eth_call:

        eth_call({
            "from": caller,
            "to": proxy,
            "data": calldata
        })

    No transaction is sent to the network.
    """

    def __init__(
        self,
        rpc: EthRpc,
        proxy: str,
        *,
        block: str = "latest",
    ) -> None:
        self.rpc = rpc
        self.proxy = proxy
        self.block = block

    def probe(
        self,
        *,
        function: str,
        caller: str,
        caller_role: str,
        calldata: str,
        candidate_implementation: str | None = None,
    ) -> AuthorizationProbeResult:
        """
        Perform one simulated authorization probe.
        """

        tx = {
            "from": caller,
            "to": self.proxy,
            "data": calldata,
        }

        try:
            result = self.rpc.call(tx, self.block)
        except Exception as exc:
            return AuthorizationProbeResult(
                proxy=self.proxy,
                function=function,
                selector=selector(function),
                caller=caller,
                caller_role=caller_role,
                mode="eth_call",
                status="evidence_gap",
                rpc_status="exception",
                error=str(exc),
                candidate_implementation=candidate_implementation,
                evidence={
                    "transaction": tx,
                    "block": self.block,
                    "broadcast": False,
                },
            )

        rpc_error = _rpc_result_error(result)

        if rpc_error is not None:
            return AuthorizationProbeResult(
                proxy=self.proxy,
                function=function,
                selector=selector(function),
                caller=caller,
                caller_role=caller_role,
                mode="eth_call",
                status="evidence_gap",
                rpc_status="error",
                error=str(rpc_error),
                candidate_implementation=candidate_implementation,
                evidence={
                    "transaction": tx,
                    "block": self.block,
                    "broadcast": False,
                },
            )

        value = _rpc_result_value(result)

        # A successful eth_call normally returns a hex string.
        return AuthorizationProbeResult(
            proxy=self.proxy,
            function=function,
            selector=selector(function),
            caller=caller,
            caller_role=caller_role,
            mode="eth_call",
            status="success",
            rpc_status="success",
            candidate_implementation=candidate_implementation,
            evidence={
                "transaction": tx,
                "block": self.block,
                "return_data": value,
                "broadcast": False,
            },
        )

    def probe_raw(
        self,
        *,
        function: str,
        caller: str,
        caller_role: str,
        calldata: str,
        candidate_implementation: str | None = None,
    ) -> AuthorizationProbeResult:
        """
        Same as probe(), but attempts to identify RPC implementations that
        return revert information through an exception.

        Kept separate so callers can use probe() for normal RpcResult handling
        and probe_raw() where provider-specific behavior needs to be captured.
        """

        tx = {
            "from": caller,
            "to": self.proxy,
            "data": calldata,
        }

        try:
            result = self.rpc.call(tx, self.block)
        except Exception as exc:
            message = str(exc)
            lowered = message.lower()

            if "revert" in lowered:
                return AuthorizationProbeResult(
                    proxy=self.proxy,
                    function=function,
                    selector=selector(function),
                    caller=caller,
                    caller_role=caller_role,
                    mode="eth_call",
                    status="reverted",
                    rpc_status="success",
                    error=message,
                    candidate_implementation=candidate_implementation,
                    evidence={
                        "transaction": tx,
                        "block": self.block,
                        "broadcast": False,
                    },
                )

            return AuthorizationProbeResult(
                proxy=self.proxy,
                function=function,
                selector=selector(function),
                caller=caller,
                caller_role=caller_role,
                mode="eth_call",
                status="evidence_gap",
                rpc_status="exception",
                error=message,
                candidate_implementation=candidate_implementation,
                evidence={
                    "transaction": tx,
                    "block": self.block,
                    "broadcast": False,
                },
            )

        rpc_error = _rpc_result_error(result)

        if rpc_error is not None:
            return AuthorizationProbeResult(
                proxy=self.proxy,
                function=function,
                selector=selector(function),
                caller=caller,
                caller_role=caller_role,
                mode="eth_call",
                status="evidence_gap",
                rpc_status="error",
                error=str(rpc_error),
                candidate_implementation=candidate_implementation,
                evidence={
                    "transaction": tx,
                    "block": self.block,
                    "broadcast": False,
                },
            )

        return AuthorizationProbeResult(
            proxy=self.proxy,
            function=function,
            selector=selector(function),
            caller=caller,
            caller_role=caller_role,
            mode="eth_call",
            status="success",
            rpc_status="success",
            candidate_implementation=candidate_implementation,
            evidence={
                "transaction": tx,
                "block": self.block,
                "return_data": _rpc_result_value(result),
                "broadcast": False,
            },
        )

    # ------------------------------------------------------------------
    # Critical upgrade probes
    # ------------------------------------------------------------------

    def probe_upgrade(
        self,
        *,
        caller: str,
        caller_role: str,
        candidate_implementation: str = DEFAULT_CANDIDATE_IMPLEMENTATION,
    ) -> AuthorizationProbeResult:
        return self.probe_raw(
            function="upgradeTo",
            caller=caller,
            caller_role=caller_role,
            calldata=calldata_upgrade_to(candidate_implementation),
            candidate_implementation=candidate_implementation,
        )

    def probe_upgrade_to_and_call(
        self,
        *,
        caller: str,
        caller_role: str,
        candidate_implementation: str = DEFAULT_CANDIDATE_IMPLEMENTATION,
        data: bytes = b"",
    ) -> AuthorizationProbeResult:
        return self.probe_raw(
            function="upgradeToAndCall",
            caller=caller,
            caller_role=caller_role,
            calldata=calldata_upgrade_to_and_call(
                candidate_implementation,
                data,
            ),
            candidate_implementation=candidate_implementation,
        )

    # ------------------------------------------------------------------
    # Basic native-function probes
    # ------------------------------------------------------------------

    def probe_execute(
        self,
        *,
        caller: str,
        caller_role: str,
        target: str,
        value: int = 0,
        data: bytes = b"",
    ) -> AuthorizationProbeResult:
        return self.probe_raw(
            function="execute",
            caller=caller,
            caller_role=caller_role,
            calldata=calldata_execute(target, value, data),
        )

    def probe_transfer_native_ownership(
        self,
        *,
        caller: str,
        caller_role: str,
        new_owner: str,
    ) -> AuthorizationProbeResult:
        return self.probe_raw(
            function="transferNativeOwnership",
            caller=caller,
            caller_role=caller_role,
            calldata=calldata_transfer_native_ownership(new_owner),
        )

    # ------------------------------------------------------------------
    # Actor matrix
    # ------------------------------------------------------------------

    def upgrade_matrix(
        self,
        *,
        owner: str = OWNER,
        attacker: str = ATTACKER,
        entry_point: str = ENTRY_POINT,
        candidate_implementation: str = DEFAULT_CANDIDATE_IMPLEMENTATION,
    ) -> list[AuthorizationProbeResult]:
        """
        Run the critical upgradeTo() matrix:

            A = owner
            B = attacker
            C = proxy/self
            D = EntryPoint
        """

        actors = (
            ("owner", owner),
            ("attacker", attacker),
            ("self", self.proxy),
            ("entrypoint", entry_point),
        )

        results: list[AuthorizationProbeResult] = []

        for role, caller in actors:
            results.append(
                self.probe_upgrade(
                    caller=caller,
                    caller_role=role,
                    candidate_implementation=candidate_implementation,
                )
            )

        return results

    def upgrade_and_call_matrix(
        self,
        *,
        owner: str = OWNER,
        attacker: str = ATTACKER,
        entry_point: str = ENTRY_POINT,
        candidate_implementation: str = DEFAULT_CANDIDATE_IMPLEMENTATION,
    ) -> list[AuthorizationProbeResult]:
        actors = (
            ("owner", owner),
            ("attacker", attacker),
            ("self", self.proxy),
            ("entrypoint", entry_point),
        )

        results: list[AuthorizationProbeResult] = []

        for role, caller in actors:
            results.append(
                self.probe_upgrade_to_and_call(
                    caller=caller,
                    caller_role=role,
                    candidate_implementation=candidate_implementation,
                    data=b"",
                )
            )

        return results

    # ------------------------------------------------------------------
    # Full matrix
    # ------------------------------------------------------------------

    def full_matrix(
        self,
        *,
        owner: str = OWNER,
        attacker: str = ATTACKER,
        entry_point: str = ENTRY_POINT,
        candidate_implementation: str = DEFAULT_CANDIDATE_IMPLEMENTATION,
    ) -> dict[str, list[AuthorizationProbeResult]]:
        """
        Run the currently well-defined authorization probes.

        Functions requiring complex ABI fixtures, such as validateUserOp and
        installPlugin, are deliberately not fabricated here. They should be
        added once valid fixtures are available.
        """

        actors = (
            ("owner", owner),
            ("attacker", attacker),
            ("self", self.proxy),
            ("entrypoint", entry_point),
        )

        result: dict[str, list[AuthorizationProbeResult]] = {
            "upgradeTo": [],
            "upgradeToAndCall": [],
            "execute": [],
            "transferNativeOwnership": [],
        }

        for role, caller in actors:
            result["upgradeTo"].append(
                self.probe_upgrade(
                    caller=caller,
                    caller_role=role,
                    candidate_implementation=candidate_implementation,
                )
            )

            result["upgradeToAndCall"].append(
                self.probe_upgrade_to_and_call(
                    caller=caller,
                    caller_role=role,
                    candidate_implementation=candidate_implementation,
                    data=b"",
                )
            )

            # Use proxy itself as target. This is only an authorization probe;
            # no transaction is broadcast and eth_call state is discarded.
            result["execute"].append(
                self.probe_execute(
                    caller=caller,
                    caller_role=role,
                    target=self.proxy,
                    value=0,
                    data=b"",
                )
            )

            result["transferNativeOwnership"].append(
                self.probe_transfer_native_ownership(
                    caller=caller,
                    caller_role=role,
                    new_owner=owner,
                )
            )

        return result


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------


def summarize_result(result: AuthorizationProbeResult) -> str:
    """
    Produce a conservative human-readable classification.

    Do not interpret every revert as authorization failure.
    """

    if result.status == "evidence_gap":
        return "EVIDENCE GAP: RPC failure; authorization not determined"

    if result.status == "success":
        if result.function == "upgradeTo":
            return (
                "CRITICAL: eth_call reached/simulated upgradeTo successfully; "
                "caller authorization appears bypassable"
            )

        return "SUCCESS: call simulation completed"

    if result.status == "reverted":
        return "REVERTED: inspect revert data before assigning authorization meaning"

    return result.status


def matrix_to_dict(
    results: Iterable[AuthorizationProbeResult],
) -> list[dict[str, Any]]:
    return [
        {
            **result.to_dict(),
            "summary": summarize_result(result),
        }
        for result in results
    ]


__all__ = [
    "ATTACKER",
    "DEFAULT_CANDIDATE_IMPLEMENTATION",
    "ENTRY_POINT",
    "OWNER",
    "AuthorizationProbe",
    "AuthorizationProbeResult",
    "SELECTORS",
    "calldata_execute",
    "calldata_transfer_native_ownership",
    "calldata_upgrade_to",
    "calldata_upgrade_to_and_call",
    "matrix_to_dict",
    "summarize_result",
]
