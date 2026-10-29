"""Тести варіанта 14: RBAC з ієрархією ролей, тимчасові права, аномалії А1 і А5."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from accesscontrol.monitor import AuditLog, Permission, ReferenceMonitor, subjects_with_access
from mydetector import DenialSpikeDetector, NewPermissionDetector, VariantDetector
from mypolicy import ClockedAuditLog, DocumentService, OperationLog, VariantPolicy, objects_accessible_by
from population import OBJECTS, SUBJECTS, FakeClock, at, build_policy

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE


def make(t=at(10)):
    clock = FakeClock(t)
    return build_policy(clock), clock


# ---------- крок 2: модель RBAC і успадкування ----------

def test_population_matches_variant():
    assert len(SUBJECTS) == 10 and len(OBJECTS) == 23 and len(set(OBJECTS)) == 23


def test_direct_role_permission():
    p, _ = make()
    d = p.evaluate("bob", "order03", W)
    assert d.allowed and "secretary" in d.reason


def test_permission_inherited_from_junior_role():
    p, _ = make()
    d = p.evaluate("carol", "protocol01", R)   # lecturer ≻ employee
    assert d.allowed and "lecturer ← employee" in d.reason


def test_senior_role_inherits_both_branches():
    p, _ = make()
    assert p.evaluate("alice", "plan01", W).allowed       # head ≻ lecturer
    assert p.evaluate("alice", "protocol02", W).allowed   # head ≻ secretary


def test_junior_does_not_get_senior_rights():
    p, _ = make()
    assert not p.evaluate("carol", "order02", D).allowed  # DELETE є лише в head


def test_combined_action_needs_all_bits():
    p, _ = make()
    assert p.evaluate("frank", "hr01", Permission.ADMIN).allowed
    assert not p.evaluate("alice", "hr01", R | W).allowed  # head має лише READ на hr


def test_cycle_in_hierarchy_rejected():
    p, _ = make()
    with pytest.raises(ValueError):
        p.add_inheritance("employee", "head")


# ---------- безпечні значення за замовчуванням ----------

def test_safe_default_unknown_subject():
    p, _ = make()
    d = p.evaluate("eve", "order01", R)
    assert not d.allowed and "safe default" in d.reason


def test_safe_default_unknown_object():
    p, _ = make()
    assert not p.evaluate("alice", "secret99", R).allowed


def test_empty_policy_denies_everything():
    p = VariantPolicy(FakeClock(at(10)))
    p.add_role("r")
    p.assign("alice", "r")
    assert not p.evaluate("alice", "doc1", R).allowed


# ---------- крок 3: додаткове правило D2 (тимчасові права) ----------

def test_temporary_role_assignment_expires():
    p, clock = make(at(11, 59))
    assert p.evaluate("dave", "order02", D).allowed
    clock.set(at(12))                                   # межа інтервалу не включається
    d = p.evaluate("dave", "order02", D)
    assert not d.allowed and "термін дії сплив" in d.reason


def test_temporary_role_not_yet_active():
    p, _ = make(at(8, 59))
    d = p.evaluate("dave", "order02", D)
    assert not d.allowed and "діє лише з" in d.reason


def test_expired_role_keeps_permanent_roles():
    p, _ = make(at(13))
    assert p.evaluate("dave", "plan01", W).allowed
    assert p.active_roles("dave") == {"lecturer", "employee"}


def test_temporary_permission_assignment_expires():
    p, clock = make(at(15, 59))
    assert p.evaluate("carol", "grades01", W).allowed
    clock.set(at(16))
    assert not p.evaluate("carol", "grades01", W).allowed
    assert p.evaluate("carol", "grades01", R).allowed   # READ безстроковий
    assert p.evaluate("alice", "grades01", W).allowed   # у head WRITE безстроковий


def test_rule_changes_result_compared_with_base_model():
    clock = FakeClock(at(13))
    with_rule, base = build_policy(clock), build_policy(clock, temporal=False)
    assert base.evaluate("dave", "order02", D).allowed
    assert not with_rule.evaluate("dave", "order02", D).allowed


# ---------- крок 4: монітор, журнали, три властивості ----------

def scenario_monitor():
    clock = FakeClock(at(10))
    oplog = OperationLog(clock)
    policy = build_policy(clock, oplog)
    mon = ReferenceMonitor(policy, ClockedAuditLog(clock))
    return DocumentService(mon, oplog, {o: "x" for o in OBJECTS}), mon, oplog, clock


def test_complete_mediation_every_call_logged():
    service, mon, _, _ = scenario_monitor()
    calls = [("read", "alice", "hr01"), ("write", "bob", "order01"),
             ("delete", "grace", "order01"), ("read", "mallory", "grades01")]
    for op, s, o in calls:
        try:
            getattr(service, op)(s, o, "y") if op == "write" else getattr(service, op)(s, o)
        except PermissionError:
            pass
    entries = mon.audit.entries()
    assert len(entries) == len(calls)
    assert [e["allowed"] for e in entries] == [True, True, False, False]


def test_enforce_raises_and_denied_operation_is_not_executed():
    service, mon, oplog, _ = scenario_monitor()
    before = len(oplog.entries())
    with pytest.raises(PermissionError, match="safe default"):
        service.delete("grace", "order01")
    assert len(oplog.entries()) == before               # зміна не відбулася
    assert service.read("alice", "order01") == "x"


def test_operation_log_contains_only_state_changes():
    service, mon, oplog, _ = scenario_monitor()
    before = len(oplog.entries())
    service.read("alice", "hr01")
    service.write("bob", "order01", "нова редакція")
    ops = [e["operation"] for e in oplog.entries()[before:]]
    assert ops == ["write"] and len(mon.audit.entries()) == 2


def test_policy_changes_go_to_operation_log():
    clock = FakeClock(at(10))
    oplog = OperationLog(clock)
    p = build_policy(clock, oplog)
    before = len(oplog.entries())
    p.revoke("bob", "secretary")
    assert oplog.entries()[before]["operation"] == "revoke"
    assert not p.evaluate("bob", "order03", W).allowed


def test_service_has_no_reference_to_policy():
    service, _, _, _ = scenario_monitor()
    assert not any(isinstance(v, VariantPolicy) for v in vars(service).values())


def test_audit_reason_for_expired_right():
    service, mon, _, clock = scenario_monitor()
    clock.set(at(12, 30))
    with pytest.raises(PermissionError):
        service.delete("dave", "order05")
    assert "термін дії сплив" in mon.audit.entries()[-1]["reason"]


# ---------- крок 5: аномалії ----------

def log_with(events):
    """events: (час, суб'єкт, об'єкт, дія); рішення — за політикою варіанта."""
    clock = FakeClock(at(9))
    mon = ReferenceMonitor(build_policy(clock), ClockedAuditLog(clock))
    for t, s, o, a in events:
        clock.set(t)
        mon.check(s, o, a)
    return mon.audit


def test_a1_denial_spike_detected():
    log = log_with([(at(10, 30, 8 * i), "mallory", f"grades{i + 1:02d}", R) for i in range(5)])
    alerts = DenialSpikeDetector(threshold=5, window=60).scan(log)
    assert len(alerts) == 1 and "mallory" in alerts[0]


def test_a1_slow_denials_not_detected():
    log = log_with([(at(10, 2 * i), "mallory", "grades01", R) for i in range(5)])
    assert DenialSpikeDetector(threshold=5, window=60).scan(log) == []


def test_a5_first_use_of_permission_detected():
    log = log_with([(at(9, 30), "dave", "plan01", R), (at(11), "dave", "order04", D)])
    alerts = NewPermissionDetector(baseline_until=at(10)).scan(log)
    assert len(alerts) == 1 and "dave" in alerts[0] and "DELETE" in alerts[0]


def test_a5_ignores_baseline_and_denials():
    log = log_with([(at(9, 30), "bob", "order01", W),         # навчання профілю
                    (at(11), "bob", "order02", W),            # уже відомо
                    (at(11), "grace", "order02", D)])         # відмова — не використання
    assert NewPermissionDetector(baseline_until=at(10)).scan(log) == []


def test_a5_object_granularity_is_more_sensitive():
    log = log_with([(at(9, 30), "carol", "plan01", W), (at(10, 5), "carol", "grades01", W)])
    assert NewPermissionDetector(at(10), granularity="action").scan(log) == []
    assert len(NewPermissionDetector(at(10), granularity="object").scan(log)) == 1


def test_variant_detector_two_alerts_and_clean_log():
    events = [(at(9, 30), "dave", "plan01", R), (at(11), "dave", "order04", D)]
    events += [(at(10, 30, 8 * i), "mallory", f"grades{i + 1:02d}", R) for i in range(6)]
    alerts = VariantDetector(baseline_until=at(10)).scan(log_with(events))
    assert len(alerts) == 2 and alerts[0].startswith("А1") and alerts[1].startswith("А5")
    assert VariantDetector(baseline_until=at(10)).scan(AuditLog()) == []


# ---------- крок 7: запити «хто» і «до чого» ----------

def test_who_has_access_changes_after_expiry():
    p, clock = make(at(10))
    assert subjects_with_access(p, SUBJECTS, "order05", D) == ["alice", "dave"]
    clock.set(at(13))
    assert subjects_with_access(p, SUBJECTS, "order05", D) == ["alice"]


def test_queries_are_dual_and_rbac_query_matches_full_scan():
    p, clock = make()
    for t in (at(10), at(13), at(17)):
        clock.set(t)
        for a in (R, W, D):
            for s in SUBJECTS:
                what = objects_accessible_by(p, s, OBJECTS, a)
                assert sorted(what) == p.accessible_objects(s, a)
                for o in OBJECTS:
                    assert (s in subjects_with_access(p, SUBJECTS, o, a)) == (o in what)
