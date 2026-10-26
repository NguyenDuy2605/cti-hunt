import pytest
from cti_hunt.contracts import ContractA, TTP, SourceSpan
from cti_hunt.stages.s4_hypothesis import select_inputs

def test_n5_scoring_prioritizes_huntable_and_target_tactic_and_confidence():
    ca = ContractA(
        report_id="R1",
        ttps=[
            # T1: Partial, low conf
            TTP(tactic="Discovery", technique_id="T1", source_span=SourceSpan(), confidence=0.2),
            # T2: Huntable, high conf, but not target tactic
            TTP(tactic="Discovery", technique_id="T2", source_span=SourceSpan(), confidence=0.9),
            # T3: Huntable, high conf, AND Lateral Movement (target tactic)
            TTP(tactic="Lateral Movement", technique_id="T3", source_span=SourceSpan(), confidence=0.8),
            # T4: Huntable, target tactic, high conf, multiple occurrences (count = 2)
            TTP(tactic="Persistence", technique_id="T4", source_span=SourceSpan(segment_id="S1"), confidence=0.8),
            TTP(tactic="Persistence", technique_id="T4", source_span=SourceSpan(segment_id="S2"), confidence=0.5),
        ]
    )
    # Fake telemetry mapping
    telemetry = {
        "T1": {"status": "partial", "sources": []},
        "T2": {"status": "huntable", "sources": []},
        "T3": {"status": "huntable", "sources": []},
        "T4": {"status": "huntable", "sources": []},
    }
    inputs, gaps = select_inputs(ca, telemetry)
    
    assert len(inputs) == 5
    assert not gaps
    
    # Check that T4 (ref 3 and 4) is at the top due to max_conf(0.8) + count(2) + target + huntable
    assert inputs[0]["ttp"].technique_id == "T4"
    assert inputs[1]["ttp"].technique_id == "T4"
    
    # Check that T3 is next (target tactic, high conf)
    assert inputs[2]["ttp"].technique_id == "T3"
    
    # Check that T2 is next (huntable, high conf, but not target tactic)
    assert inputs[3]["ttp"].technique_id == "T2"
    
    # T1 is last (partial)
    assert inputs[4]["ttp"].technique_id == "T1"

