"""N5 regressions with synthetic ledgers, tools and records only."""
import json
from types import SimpleNamespace

import pytest
import yaml
from langgraph.types import Command

from cti_hunt import approval
from cti_hunt.agent.graph import (AgentGuardError, LLMPlanner, PipelinePlanner, build_graph, open_sqlite_graph)
from cti_hunt.agent.limits import hypothesis_budget
from cti_hunt.llm.budget import Ledger, BudgetError
from cti_hunt.contracts import ContractB, Evidence

PROMPT = {'sections': {'SYSTEM': 'synthetic', 'USER': '{context}'}}
CFG = {'max_rounds': 20, 'max_total_independent_hypotheses': 2, 'max_hypotheses_per_round': 2,
       'max_pivot_depth': 2, 'triage': {'max_pivots_per_round': 3, 'max_queries_total': 20}}


def initial():
    return {'report_id': 'SYN', 'remaining_refs': [0, 1, 2], 'history': [], 'generated_ids': []}


class Tools:
    executed = 0

    def propose(self, state, decision, run_dir):
        return [ContractB(hypothesis_id=f'SYN-H{i}', behavior='synthetic', scope='all', timeframe='all time',
                          evidence=Evidence(data_source='security', event_ids=[4688], key_fields=['Image']),
                          linked_ttps=['T1047']) for i in range(2)]

    def execute(self, state, approved):
        self.executed += 1
        return {}

    def record(self, state):
        return 'synthetic-record'


@pytest.mark.parametrize('decision', ['approved', 'rejected'])
def test_total_cap_survives_checkpoint_and_last_review(tmp_path, decision):
    tools = Tools()
    calls = []
    def planner(view):
        calls.append(view)
        return PipelinePlanner()(view)
    db, thread = tmp_path / 'checkpoint.sqlite', {'configurable': {'thread_id': 'synthetic'}}
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        assert '__interrupt__' in graph.invoke(initial(), thread)
    form_path = tmp_path / 'round_01' / approval.REVIEW_FILE
    form = yaml.safe_load(form_path.read_text(encoding='utf-8'))
    form['nguoi_duyet'] = 'synthetic tester'
    for row in form['gia_thuyet']:
        row.update(quyet_dinh=decision, ly_do='synthetic decision')
    form_path.write_text(yaml.safe_dump(form), encoding='utf-8')
    with open_sqlite_graph(planner, tools, CFG, tmp_path, db) as graph:
        out = graph.invoke(Command(resume=True), thread)
    assert tools.executed == int(decision == 'approved')
    assert len(calls) == 1 and calls[0]['hypothesis_budget']['remaining'] == 2
    assert out['record'] == 'synthetic-record'
    assert out['history'][-1]['hypothesis_budget'] == {'used': 2, 'remaining': 0, 'limit': 2}
    assert 'trần tổng' in out['decision']['reason']


def test_pivots_do_not_count_as_independent_hypotheses():
    state = {'history': [{'decision': {'action': 'hunt'}, 'generated_ids': ['H1']},
                         {'decision': {'action': 'pivot'}, 'generated_ids': ['H2', 'H3']}]}
    assert hypothesis_budget(state, CFG) == {'used': 1, 'remaining': 1, 'limit': 2}


@pytest.mark.parametrize('invalid', [0, -1, True, 1.5, '50', None])
def test_bad_total_cap_rejected(tmp_path, invalid):
    with pytest.raises(AgentGuardError, match='max_total_independent_hypotheses'):
        build_graph(PipelinePlanner(), Tools(), {**CFG, 'max_total_independent_hypotheses': invalid}, tmp_path)


def test_tool_cannot_bypass_total_cap(tmp_path):
    with pytest.raises(AgentGuardError, match='vượt trần tổng'):
        build_graph(PipelinePlanner(), Tools(), {**CFG, 'max_total_independent_hypotheses': 1}, tmp_path).invoke(
            initial(), {'configurable': {'thread_id': 'overshoot'}})
    assert not (tmp_path / 'round_01' / approval.REVIEW_FILE).exists()


def test_budget_reaches_planner_and_log_without_ledger_path(tmp_path):
    ledger = Ledger(tmp_path / 'budget.sqlite')
    ledger.init('1')
    tools = Tools()
    tools.llm_rules = SimpleNamespace(budget_ledger=ledger.path)
    views = []
    def planner(view):
        views.append(view)
        return {'action': 'stop', 'reason': 'synthetic'}
    out = build_graph(planner, tools, CFG, tmp_path).invoke(initial(), {'configurable': {'thread_id': 'budget'}})
    assert views[0]['api_budget']['remaining_usd'] == '1.000000'
    assert 'ledger' not in views[0]['api_budget']
    assert out['history'][0]['api_budget'] == views[0]['api_budget']
    ledger.path.unlink()
    with pytest.raises(BudgetError):
        build_graph(planner, tools, CFG, tmp_path).invoke(initial(), {'configurable': {'thread_id': 'missing'}})


class Client:
    model_id = 'synthetic'
    def __init__(self, responses):
        self.responses = iter(responses)
        self.views = []
    def complete_json(self, system, user, schema, log):
        self.views.append(json.loads(user))
        log({'input_tokens': 10, 'output_tokens': 2})
        return next(self.responses)


def test_memory_events_logged_once_and_read_is_bounded(tmp_path):
    client = Client([
        {'action': 'tra_hunt_memory', 'reason': 'search'},
        {'action': 'doc_hunt_record', 'doc_hunt_record': {'record_id': 'record-0'}, 'reason': 'read'},
        {'action': 'stop', 'reason': 'done'}])
    class Store:
        def find(self, **kwargs):
            return [{'record_id': f'record-{i}'} for i in range(100)]
        def read(self, record_id):
            return {'record': {'report_id': 'SYN', 'history': [], 'observations': [],
                               'attack_labels': 'SENTINEL', 'executed_specs': []},
                    'markdown': 'SENTINEL' * 10000}
    planner = LLMPlanner(client, PROMPT, tmp_path)
    planner.store = Store()
    assert planner({})['action'] == 'stop'
    logs = [json.loads(l) for l in (tmp_path / 'agent_plan_requests.jsonl').read_text(encoding='utf-8').splitlines()]
    assert [len(l['api_events']) for l in logs] == [1, 1, 1]
    assert sum(e['input_tokens'] for l in logs for e in l['api_events']) == 30
    search = client.views[1]['memory_tool_results'][0]
    assert search['truncated'] and len(search['result']) == 10
    assert 'SENTINEL' not in json.dumps(client.views)
    assert len(client.views[2]['memory_tool_results'][1]['result']['summary_json_preview']) <= 12000


def test_unknown_memory_id_is_never_read(tmp_path):
    client = Client([{'action': 'doc_hunt_record', 'doc_hunt_record': {'record_id': '../unlisted'}, 'reason': 'read'},
                     {'action': 'stop', 'reason': 'done'}])
    class Store:
        def read(self, record_id):
            raise AssertionError('must not read unlisted ID')
    planner = LLMPlanner(client, PROMPT, tmp_path)
    planner.store = Store()
    planner({})
    assert client.views[1]['memory_tool_results'][0]['error'] == 'ValueError'


@pytest.mark.parametrize('hide', [False, True])
def test_budget_is_refreshed_between_memory_calls(tmp_path, monkeypatch, hide):
    import cti_hunt.agent.graph as graph_module
    snapshots = iter([{'remaining_usd': '1', 'pending_count': 0}, {'remaining_usd': '0', 'pending_count': 0}])
    monkeypatch.setattr(graph_module, 'api_budget', lambda *clients: next(snapshots))
    client = Client([{'action': 'tra_hunt_memory', 'reason': 'search'}])
    decision = LLMPlanner(client, PROMPT, tmp_path, hide_budget_amounts=hide)({})
    assert len(client.views) == 1 and decision['action'] == 'stop'
    assert 'ngân sách' in decision['reason']


def test_v2_hides_amounts_in_payload_but_keeps_local_budget_and_stop_guard(tmp_path):
    from cti_hunt.agent.limits import api_budget
    ledger = Ledger(tmp_path / 'synthetic_budget.sqlite')
    ledger.init('0.644')
    client = Client([{'action': 'stop', 'reason': 'synthetic exhausted search'}])
    client.budget_ledger = ledger.path
    client.model_id = 'claude-sonnet-5'
    client.max_output_tokens = 4096
    tools = Tools()
    planner = LLMPlanner(client, PROMPT, tmp_path, hide_budget_amounts=True)
    state = initial()
    out = build_graph(planner, tools, CFG, tmp_path).invoke(state, {'configurable': {'thread_id': 'v2-budget'}})
    assert 'api_budget' not in client.views[0]
    assert client.views[0]['api_call_allowed'] is True
    assert '0.644' not in json.dumps(client.views)
    assert out['history'][0]['api_budget']['remaining_usd'] == '0.644000'
    assert 'api_budget' not in json.loads((tmp_path / 'agent_plan_requests.jsonl').read_text())['user']
    assert api_budget(client)['remaining_usd'] == '0.644000'
    # Code stops before a planning call when the synthetic ledger cannot reserve it.
    empty = Ledger(tmp_path / 'empty_budget.sqlite')
    empty.init('0.001')
    client.budget_ledger = empty.path
    decision = planner({'api_budget': {'remaining_usd': '999', 'pending_count': 0}})
    assert decision['action'] == 'stop' and 'ngân sách' in decision['reason']
    assert len(client.views) == 1
