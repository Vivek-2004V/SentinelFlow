"""
Attack Chain Reconstruction Engine.

Maps detected threats to stages of the Cyber Kill Chain / MITRE ATT&CK framework.
"""
from __future__ import annotations

from app.schemas.detection import (
    THREAT_TO_STAGE,
    AttackChain,
    FusedThreat,
    KillChainStage,
)


def reconstruct_attack_chain(threats: list[FusedThreat]) -> AttackChain:
    """
    Builds an ordered sequence of attack stages observed for a host.
    """
    if not threats:
        return AttackChain(src_ip="")

    src_ip = threats[0].src_ip
    all_threat_types = set()
    stages_set = set()

    first_seen = threats[0].window_start
    last_seen = threats[-1].window_end

    for t in threats:
        all_threat_types.update(t.threat_types)
        first_seen = min(first_seen, t.window_start)
        last_seen = max(last_seen, t.window_end)
        for tt in t.threat_types:
            if tt in THREAT_TO_STAGE:
                stages_set.add(THREAT_TO_STAGE[tt])

    # Sort stages according to standard kill-chain ordering
    stage_order = [
        KillChainStage.RECONNAISSANCE,
        KillChainStage.WEAPONISATION,
        KillChainStage.DELIVERY,
        KillChainStage.EXPLOITATION,
        KillChainStage.INSTALLATION,
        KillChainStage.C2,
        KillChainStage.ACTIONS_ON_OBJECTIVES,
    ]
    ordered_stages = [s for s in stage_order if s in stages_set]

    duration = (last_seen - first_seen).total_seconds()

    return AttackChain(
        src_ip=src_ip,
        stages=ordered_stages,
        threat_types=list(all_threat_types),
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=max(0.0, duration),
        is_multi_stage=len(ordered_stages) > 1,
    )
