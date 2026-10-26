import argparse
import json
from pathlib import Path
from cti_hunt.contracts import ContractA

def verify(contract_path: Path, reference_path: Path):
    with open(contract_path, encoding='utf-8') as f:
        ca = json.load(f)
    
    with open(reference_path, encoding='utf-8') as f:
        ref = json.load(f)
    
    extracted_ttps = ca.get("ttps", [])
    checks = ref.get("checks", [])
    
    print(f"Contract A has {len(extracted_ttps)} TTPs.")
    print(f"Reference has {len(checks)} checks.")
    print("-" * 50)
    
    passed = 0
    for check in checks:
        check_id = check["check_id"]
        expected_techs = set(check["technique_ids"])
        expected_segments = set(check["segment_ids"])
        
        # Check if any TTP matches BOTH a technique AND a segment from the check
        found = False
        matching_ttps = []
        for ttp in extracted_ttps:
            tech = ttp["technique_id"]
            seg = ttp.get("source_span", {}).get("segment_id", "")
            if tech in expected_techs and seg in expected_segments:
                found = True
                matching_ttps.append(ttp)
        
        if found:
            print(f"✅ {check_id} PASS: Found {len(matching_ttps)} matching TTP(s) for techniques {expected_techs}.")
            passed += 1
        else:
            print(f"❌ {check_id} FAIL: Expected techniques {expected_techs} in segments {expected_segments}.")
            # See if we found the segment but mapped to different tech, or tech but different segment
            seg_matches = [t for t in extracted_ttps if t.get("source_span", {}).get("segment_id") in expected_segments]
            tech_matches = [t for t in extracted_ttps if t["technique_id"] in expected_techs]
            if seg_matches:
                print(f"    - Segment found, but mapped to: {[t['technique_id'] for t in seg_matches]}")
            if tech_matches:
                print(f"    - Technique found, but in segments: {[t.get('source_span', {}).get('segment_id') for t in tech_matches]}")
    
    print("-" * 50)
    print(f"Score: {passed}/{len(checks)} checks passed.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("contract")
    parser.add_argument("reference")
    args = parser.parse_args()
    verify(Path(args.contract), Path(args.reference))
