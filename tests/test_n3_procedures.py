import json

import pytest

from cti_hunt.attack import procedures as P
from cti_hunt.attack.retrieval import TechniqueIndex
from cti_hunt.eval import proc_examples as D


def _ref(eid):
    return [{"source_name": "mitre-attack", "external_id": eid}]


def _uses(rid, src, tech, text, cite="Some Blog", **kw):
    return {"type": "relationship", "id": f"relationship--{rid}", "relationship_type": "uses",
            "source_ref": src, "target_ref": tech, "description": text,
            "external_references": [{"source_name": cite}], **kw}


@pytest.fixture
def stix(tmp_path):
    objects = []
    for tid, name, desc, platforms in [
            ("T1047", "Windows Management Instrumentation", "WMI executes commands.", ["Windows"]),
            ("T1059", "Command and Scripting Interpreter", "Interpreters run commands.", ["Windows", "Linux"]),
            ("T1059.001", "PowerShell", "PowerShell runs scripts.", ["Windows"]),
            ("T1098", "Account Manipulation", "Accounts are changed.", ["Windows"]),
            ("T9999", "Linux Only", "Only on Linux.", ["Linux"])]:
        objects.append({"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name, "description": desc,
                        "x_mitre_platforms": platforms, "external_references": _ref(tid), "kill_chain_phases": []})
    for sid, typ, eid, name in [("intrusion-set--apt29", "intrusion-set", "G0016", "APT29"),
                                ("intrusion-set--other", "intrusion-set", "G0001", "Other Group"),
                                ("malware--apt29", "malware", "S0001", "Apt29Malware"),
                                ("tool--other", "tool", "S0002", "OtherTool"),
                                ("campaign--solar", "campaign", "C0024", "SolarWinds Compromise"),
                                ("campaign--other", "campaign", "C0099", "Other Campaign")]:
        objects.append({"type": typ, "id": sid, "name": name, "external_references": _ref(eid)})
    objects += [
        {"type": "relationship", "id": "relationship--r0", "relationship_type": "uses",
         "source_ref": "intrusion-set--apt29", "target_ref": "malware--apt29"},
        {"type": "relationship", "id": "relationship--r00", "relationship_type": "attributed-to",
         "source_ref": "campaign--solar", "target_ref": "intrusion-set--apt29"},
        {"type": "relationship", "id": "relationship--r000", "relationship_type": "attributed-to",
         "source_ref": "campaign--other", "target_ref": "intrusion-set--other"},
        _uses("a1", "intrusion-set--other", "attack-pattern--T1047",
              "[Other Group](https://attack.mitre.org/groups/G0001) used WMIC to start zebracommand remotely."
              "(Citation: Some Blog)"),
        _uses("a2", "intrusion-set--apt29", "attack-pattern--T1047", "APT29 used WMI."),
        _uses("a3", "malware--apt29", "attack-pattern--T1059.001", "The malware runs PowerShell."),
        _uses("a4", "campaign--solar", "attack-pattern--T1047", "During the campaign WMI was used."),
        _uses("a5", "intrusion-set--other", "attack-pattern--T1059.001", "Other used PowerShell loaders.",
              cite="FireEye POSHSPY April 2017"),
        _uses("a6", "tool--other", "attack-pattern--T1059.001",
              "[OtherTool](https://attack.mitre.org/software/S0002) can run "
              "[PowerShell](https://attack.mitre.org/techniques/T1059/001) <code>-enc</code> scripts (T1059.001)."),
        _uses("a7", "intrusion-set--other", "attack-pattern--T9999", "Linux persistence."),
        _uses("a8", "campaign--other", "attack-pattern--T1098", "Accounts were added to a privileged group."),
        _uses("a9", "intrusion-set--other", "attack-pattern--T1098", "Revoked use.", revoked=True),
    ]
    path = tmp_path / "attack.json"
    path.write_text(json.dumps({"objects": objects}), encoding="utf-8")
    return path


def test_load_excludes_eval_report_citations_and_apt29_actors(stix):
    data = P.load(stix)
    by_id = {p["id"].split("--")[1]: p for p in data["procedures"]}
    assert set(by_id) == {"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8"}       # bỏ quan hệ đã thu hồi
    assert by_id["a2"]["loai_tru"] == ["chu_the_apt29"]                          # nhóm
    assert by_id["a3"]["loai_tru"] == ["chu_the_apt29"]                          # phần mềm nhóm dùng
    assert by_id["a4"]["loai_tru"] == ["chu_the_apt29"]                          # campaign gắn với nhóm
    assert by_id["a5"]["loai_tru"] == ["trich_report_danh_gia"]
    assert not by_id["a1"]["loai_tru"] and not by_id["a8"]["loai_tru"]         # campaign của nhóm khác vẫn dùng
    assert {a["vai_tro"] for a in data["chu_the_apt29"]} == {"nhom", "phan_mem_nhom", "campaign_gan_nhom"}
    assert P.summary(data) == {"tong": 8, "ky_thuat": 4, "trich_report_danh_gia": 1, "chu_the_apt29": 3,
                               "loai_tru_hop": 4, "con_lai": 4, "con_lai_windows": 3}


def test_clean_text_removes_links_ids_tags_and_flags_leaks(stix):
    a6 = next(p for p in P.load(stix)["procedures"] if p["id"].endswith("a6"))
    assert a6["text"] == "OtherTool can run PowerShell -enc scripts ()."
    assert a6["co_link_hoac_ma_ky_thuat"]
    a1 = next(p for p in P.load(stix)["procedures"] if p["id"].endswith("a1"))
    assert a1["text"] == "Other Group used WMIC to start zebracommand remotely." and not a1["co_link_hoac_ma_ky_thuat"]
    assert P.clean_text("uses T1047 here")[1] and P.clean_text("[a](https://x.org/b)")[0] == "a"


def test_dev_set_is_deterministic_windows_only_and_split(stix):
    procs = P.load(stix)["procedures"]
    items = D.build_dev_set(procs, size=3, held_out=1, seed=7)
    assert items == D.build_dev_set(procs, size=3, held_out=1, seed=7)
    assert {i["id"].split("--")[1] for i in items} == {"a1", "a6", "a8"}            # không bị loại, chỉ Windows
    assert [i["tap"] for i in items].count("giu_lai") == 1
    with pytest.raises(ValueError, match="Không đủ"):
        D.build_dev_set(procs, size=4, held_out=1)
    manifest = D.dev_set_manifest(items, "sha")
    assert manifest["so_cau"] == 3 and manifest["chinh"]["so_cau"] == 2 and manifest["giu_lai"]["so_cau"] == 1


def test_index_with_procedures_excludes_dev_set_and_keeps_default(stix):
    procs = P.load(stix)["procedures"]
    assert TechniqueIndex.from_stix(stix).search("zebracommand", 3) == []      # mặc định chỉ định nghĩa
    with_examples = TechniqueIndex.from_stix(stix, procedures=[p for p in procs if not p["loai_tru"]])
    found = with_examples.search("zebracommand", 3)
    assert found[0]["technique_id"] == "T1047" and "zebracommand" not in json.dumps(found)
    dev = [i for i in D.build_dev_set(procs, size=3, held_out=1, seed=7) if i["id"].endswith("a1")]
    kept = D.index_procedures(procs, dev)
    assert all(not p["loai_tru"] for p in kept) and not any(p["id"].endswith("a1") for p in kept)
    index = TechniqueIndex.from_stix(stix, procedures=kept)
    assert index.search("zebracommand", 3) == [] and index.example_count == 3   # a6, a7 (Linux), a8


def test_retrieval_recall_counts_exact_and_parent_hits(stix):
    procs = P.load(stix)["procedures"]
    index = TechniqueIndex.from_stix(stix)
    items = [{"id": "x1", "technique_id": "T1059.001", "text": "PowerShell runs scripts", "co_link_hoac_ma_ky_thuat": False},
             {"id": "x2", "technique_id": "T1098", "text": "zzzz unknown words", "co_link_hoac_ma_ky_thuat": True}]
    out = D.retrieval_recall(index, items, k=2, batch=2)
    assert out["theo_cau"]["tat_ca"] == {"so_cau": 2, "dung_ma": 1, "cung_ky_thuat_cha": 1,
                                         "recall_dung_ma": 0.5, "recall_cung_cha": 0.5}
    assert out["theo_cau"]["co_link_ma"]["dung_ma"] == 0 and out["theo_lo"]["tat_ca"]["so_cau"] == 2
    assert procs  # dùng fixture để giữ dữ liệu cùng phiên bản
