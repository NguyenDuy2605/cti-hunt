"""Shared N5 budgets; counts include rejected hypotheses, exclude pivots."""
from decimal import Decimal
from pathlib import Path

from ..llm.budget import Ledger, min_reserve, usd


def hypothesis_budget(state, cfg):
    limit = cfg.get('max_total_independent_hypotheses', 50)
    if type(limit) is not int or limit < 1:
        raise ValueError('max_total_independent_hypotheses phải là số nguyên dương')
    used = sum(len(h.get('generated_ids') or []) for h in state.get('history') or []
               if h['decision']['action'] == 'hunt')
    return {'used': used, 'remaining': max(0, limit - used), 'limit': limit}


def api_budget(*clients):
    clients = [c for c in clients if getattr(c, 'budget_ledger', None)]
    paths = {Path(c.budget_ledger).resolve() for c in clients}
    if len(paths) > 1:
        raise ValueError('Planner và công cụ phải dùng cùng sổ ngân sách')
    if not paths:
        return None
    status = Ledger(paths.pop()).status()  # Do not swallow an unreadable/uninitialized ledger.
    # Mỗi lời gọi giữ trước toàn bộ max_tokens: còn ít hơn mức này thì lời gọi kế tiếp chắc chắn bị từ chối.
    reserves = [r for c in clients
                if (r := min_reserve(getattr(c, 'model_id', ''), getattr(c, 'max_output_tokens', 0))) is not None]
    return {**{k: status[k] for k in ('limit_usd', 'known_cost_usd', 'reserved_usd', 'remaining_usd')},
            'pending_count': len(status['pending']),
            'min_reserve_usd': usd(max(reserves)) if reserves else None}


def budget_stop_reason(budget):
    if budget is None:
        return ''
    if budget['pending_count']:
        return 'sổ API có yêu cầu chưa rõ chi phí; cần đối soát trước khi gọi tiếp'
    remaining = Decimal(budget['remaining_usd'])
    if remaining <= 0:
        return 'đã hết ngân sách API cục bộ'
    need = budget.get('min_reserve_usd')
    if need is not None and remaining < Decimal(need):
        return (f"ngân sách API cục bộ còn {budget['remaining_usd']} USD, không đủ giữ trước một lời gọi "
                f"(tối thiểu {need} USD)")
    return ''
