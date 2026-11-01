"""Демонстрація підсистеми розмежування доступу (ЛР2, варіант 14).

Запуск з каталогу lab02_access_control:
  python demo.py              # вивід у консоль
  python demo.py --save DIR   # додатково зберегти журнали audit_log.jsonl, operation_log.jsonl
"""
from __future__ import annotations

import pathlib
import sys

from accesscontrol.monitor import Permission, ReferenceMonitor, subjects_with_access
from mydetector import DenialSpikeDetector, NewPermissionDetector, VariantDetector
from mypolicy import ClockedAuditLog, DocumentService, OperationLog, fmt_ts, objects_accessible_by
from population import OBJECTS, SUBJECTS, FakeClock, at, build_policy

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE
BASELINE_UNTIL = at(10)

# (час, суб'єкт, об'єкт, дія, очікуване рішення з D2, коментар)
CASES = [
    (at(10), "alice", "hr01", R, True, "head читає кадрові"),
    (at(10), "alice", "order02", D, True, "head видаляє наказ"),
    (at(10), "bob", "order03", W, True, "secretary"),
    (at(10), "bob", "hr01", R, False, "немає права"),
    (at(10), "carol", "protocol01", R, True, "успадкування employee"),
    (at(10), "carol", "grades01", W, True, "сесія триває"),
    (at(17), "carol", "grades01", W, False, "D2: сесія закінчилась"),
    (at(10), "dave", "order02", D, True, "в. о. завідувача"),
    (at(13), "dave", "order02", D, False, "D2: в. о. закінчилось"),
    (at(13), "dave", "plan01", W, True, "лишився lecturer"),
    (at(10), "frank", "hr02", D, True, "hr: R|W|D"),
    (at(10), "grace", "order01", R, True, "опублікований наказ"),
    (at(10), "grace", "order02", R, False, "student"),
    (at(10), "mallory", "grades02", R, False, "student"),
    (at(10), "trent", "hr03", R, True, "auditor читає все"),
    (at(10), "trent", "hr03", W, False, "auditor лише читає"),
    (at(10), "eve", "order01", R, False, "невідомий суб'єкт"),
]

# Серія звернень через DocumentService: (час, суб'єкт, операція, об'єкт)
SCENARIO = [
    (at(9, 5), "alice", "read", "hr01"), (at(9, 10), "alice", "write", "grades01"),
    (at(9, 12), "bob", "read", "order01"), (at(9, 13), "bob", "write", "order02"),
    (at(9, 20), "bob", "write", "protocol01"), (at(9, 25), "carol", "read", "plan01"),
    (at(9, 26), "carol", "write", "plan01"), (at(9, 30), "carol", "read", "grades01"),
    (at(9, 35), "dave", "read", "plan02"), (at(9, 40), "erin", "read", "protocol02"),
    (at(9, 45), "frank", "read", "hr02"), (at(9, 46), "frank", "write", "hr02"),
    (at(9, 50), "grace", "read", "order01"), (at(9, 52), "heidi", "read", "order01"),
    (at(9, 55), "trent", "read", "hr03"), (at(9, 57), "grace", "read", "order02"),
    # ---- кінець базового періоду (10:00) ----
    (at(10, 5), "carol", "write", "grades01"),
    *[(at(10, 30, 8 * i), "mallory", "read", f"grades{i + 1:02d}") for i in range(6)],
    (at(11), "dave", "delete", "order04"),
    (at(12, 30), "dave", "delete", "order05"), (at(12, 31), "dave", "delete", "order05"),
    (at(15), "erin", "write", "grades02"), (at(16, 30), "erin", "write", "grades02"),
    (at(17), "trent", "read", "order03"),
]


def mark(allowed: bool) -> str:
    return "дозвіл" if allowed else "відмова"


def show_decisions() -> None:
    print("== 1. Таблиця очікуваних і фактичних рішень (з D2 / базова RBAC без D2)")
    clock = FakeClock(at(10))
    policy, base = build_policy(clock), build_policy(clock, temporal=False)
    mismatches = 0
    for t, s, o, a, expected, note in CASES:
        clock.set(t)
        d, b = policy.evaluate(s, o, a), base.evaluate(s, o, a)
        mismatches += d.allowed != expected
        flag = "" if d.allowed == expected else "  !!"
        diff = "  ← D2" if d.allowed != b.allowed else ""
        print(f"{fmt_ts(t)[11:]} {s:7} {a.name:6} {o:10} очік. {mark(expected):7} "
              f"факт. {mark(d.allowed):7} база {mark(b.allowed):7}{diff}{flag}")
        print(f"      {d.reason} ({note})")
    print(f"Збіг очікуваних і фактичних: {len(CASES) - mismatches}/{len(CASES)}")


def run_scenario(save_dir: pathlib.Path | None) -> None:
    print("\n== 2. Серія звернень через монітор (DocumentService → ReferenceMonitor)")
    clock = FakeClock(at(9))
    oplog = OperationLog(clock)
    policy = build_policy(clock, oplog)
    policy_changes = len(oplog.entries())
    mon = ReferenceMonitor(policy, ClockedAuditLog(clock))
    service = DocumentService(mon, oplog, {o: f"текст {o}" for o in OBJECTS})
    calls = denied = 0
    for t, s, op, o in SCENARIO:
        clock.set(t)
        calls += 1
        try:
            if op == "read":
                service.read(s, o)
            elif op == "write":
                service.write(s, o, f"нова редакція {o}")
            else:
                service.delete(s, o)
        except PermissionError:
            denied += 1
    entries = mon.audit.entries()
    print(f"Викликів монітора: {calls}, записів реєстраційного журналу: {len(entries)}, "
          f"з них відмов: {denied}")
    print(f"Операційний журнал: {len(oplog.entries())} записів "
          f"({policy_changes} змін політики + {len(oplog.entries()) - policy_changes} змін об'єктів)")

    print("\nРеєстраційний журнал (після базового періоду):")
    for r in entries:
        if r["ts"] >= BASELINE_UNTIL:
            print(f"  {fmt_ts(r['ts'])[11:]}:{int(r['ts']) % 60:02d} {r['subject']:7} "
                  f"{r['action']:6} {r['object']:10} {mark(r['allowed']):7} {r['reason']}")
    print("\nОпераційний журнал (зміни об'єктів):")
    for r in oplog.entries()[policy_changes:]:
        print(f"  {fmt_ts(r['ts'])[11:]} {r['actor']:7} {r['operation']:6} {r['target']} {r['details']}")

    print("\n== 3. Детектори аномалій (А1 поріг 5 відмов / 60 с; А5 базовий період до 10:00)")
    for alert in VariantDetector(BASELINE_UNTIL).scan(mon.audit):
        print("  " + alert)
    print("  А5 з granularity='object':")
    for alert in NewPermissionDetector(BASELINE_UNTIL, granularity="object").scan(mon.audit):
        print("    " + alert)
    clean = ReferenceMonitor(policy, ClockedAuditLog(clock))
    for t, s, op, o in SCENARIO[:15]:
        clock.set(t)
        clean.check(s, o, {"read": R, "write": W, "delete": D}[op])
    clock.set(at(11))
    clean.check("bob", "order03", W)
    print(f"  «Чистий» журнал ({len(clean.audit.entries())} записів): "
          f"{VariantDetector(BASELINE_UNTIL).scan(clean.audit)}")

    if save_dir:
        save_dir.mkdir(parents=True, exist_ok=True)
        (save_dir / "audit_log.jsonl").write_text(mon.audit.dump() + "\n", encoding="utf-8")
        (save_dir / "operation_log.jsonl").write_text(oplog.dump() + "\n", encoding="utf-8")


def show_queries() -> None:
    print("\n== 4. Запити «хто має доступ» і «до чого має доступ»")
    clock = FakeClock(at(10))
    policy = build_policy(clock)
    for t in (at(10), at(13)):
        clock.set(t)
        print(f"[{fmt_ts(t)}]")
        print("  хто видаляє order05:", subjects_with_access(policy, SUBJECTS, "order05", D))
        print("  хто пише grades03: ", subjects_with_access(policy, SUBJECTS, "grades03", W))
        print("  що видаляє dave:   ", objects_accessible_by(policy, "dave", OBJECTS, D))
        print("  ролі dave:         ", sorted(policy.active_roles("dave")))
    clock.set(at(10))
    print("  що читає carol:", policy.accessible_objects("carol", R))
    pairs = consistent = 0
    for t in (at(10), at(13), at(17)):
        clock.set(t)
        for a in (R, W, D):
            for s in SUBJECTS:
                what = set(objects_accessible_by(policy, s, OBJECTS, a))
                assert what == set(policy.accessible_objects(s, a))
                for o in OBJECTS:
                    pairs += 1
                    consistent += (s in subjects_with_access(policy, SUBJECTS, o, a)) == (o in what)
    print(f"Узгодженість «s ∈ хто(o) ⇔ o ∈ що(s)»: {consistent}/{pairs} пар "
          f"(10:00, 13:00, 17:00 × READ/WRITE/DELETE)")

    print("\n== 5. Тимчасове право спливає під час серії звернень (dave, DELETE order05)")
    mon = ReferenceMonitor(policy, ClockedAuditLog(clock))
    for t in (at(11, 58), at(11, 59), at(12), at(12, 1)):
        clock.set(t)
        d = mon.check("dave", "order05", D)
        print(f"  {fmt_ts(t)[11:]} {mark(d.allowed):7} {d.reason}; "
              f"хто видаляє order05: {subjects_with_access(policy, SUBJECTS, 'order05', D)}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    save = pathlib.Path(sys.argv[sys.argv.index("--save") + 1]) if "--save" in sys.argv else None
    show_decisions()
    run_scenario(save)
    show_queries()
