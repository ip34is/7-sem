"""Тести варіанта 14: bcrypt, квота спроб у ковзному вікні, одноразові коди відновлення."""
import hashlib
import hmac
import math

import bcrypt
import pytest

from auth import passwords
from auth.anderson import entropy_bits, min_length, required_space
from auth.lockout import SlidingWindowLockout
from auth.passwords import hash_password, hash_password_insecure, needs_rehash, verify_password
from auth.recovery import ALPHABET, RecoveryCodes, code_hash, generate_codes, normalize
from auth.service import Authenticator, Result

T0 = 1_800_000_000.0   # довільна мітка часу для сценаріїв


# ---------- формула Андерсона ----------

def test_anderson_lecture_example():
    G = required_space(10, 90, 1e-6)
    assert G == pytest.approx(1.296e12) and min_length(G, 95) == 7
    assert round(entropy_bits(95, 7), 1) == 46.0


def test_anderson_variant_14():
    G = required_space(12, 120, 1e-6)
    assert G == pytest.approx(2.0736e12)
    assert [min_length(G, a) for a in (26, 62, 95)] == [9, 7, 7]


def test_lockout_lowers_required_space():
    r_eff = 5 / 15                                    # 5 невдач за 15 хв
    assert required_space(r_eff, 120, 1e-6) == pytest.approx(required_space(12, 120, 1e-6) / 36)
    assert min_length(required_space(r_eff, 120, 1e-6), 95) == 6


# ---------- hash_password / verify_password ----------

def test_roundtrip():
    h = hash_password("correct horse")
    assert verify_password(h, "correct horse")


def test_wrong_password_rejected():
    assert not verify_password(hash_password("correct horse"), "wrong")


def test_salt_is_unique():
    a, b = hash_password("same"), hash_password("same")
    assert a != b and a.split("$")[3] != b.split("$")[3]


def test_storage_format_and_cost():
    scheme, version, cost, salt, digest = hash_password("x").split("$")
    assert (scheme, version, cost) == ("bcrypt", "2b", "12")
    assert len(salt) == 22 and len(digest) == 31   # 16 байтів солі, 23 байти хешу в алфавіті bcrypt


def test_pepper_is_applied():
    h = hash_password("pw")
    _, version, cost, salt, digest = h.split("$")
    plain = bcrypt.hashpw(b"pw", f"${version}${cost}${salt}".encode()).decode()
    assert not plain.endswith(digest)                # пароль без перцю дає інший хеш


def test_other_pepper_fails(monkeypatch):
    h = hash_password("pw")
    monkeypatch.setattr(passwords, "PEPPER", b"another-test-pepper")
    assert not verify_password(h, "pw")


def test_long_password_not_truncated():
    base = "x" * 72
    h = hash_password(base + "A")
    assert verify_password(h, base + "A") and not verify_password(h, base + "B")


def test_unicode_password():
    h = hash_password("пароль-тест-ü")
    assert verify_password(h, "пароль-тест-ü") and not verify_password(h, "пароль-тест-u")


def test_constant_time_compare_used(monkeypatch):
    calls = []
    real = hmac.compare_digest
    monkeypatch.setattr(passwords.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    verify_password(hash_password("pw"), "pw")
    assert calls == [1]


@pytest.mark.parametrize("bad", ["", "bcrypt$2b$12$short$x", "sha256$2b$12$" + "a" * 22 + "$" + "b" * 31,
                                 "bcrypt$2b$99$" + "a" * 22 + "$" + "b" * 31])
def test_malformed_stored_value_rejected(bad):
    assert not verify_password(bad, "pw")


def test_needs_rehash_for_weaker_cost():
    assert needs_rehash(hash_password("pw", cost=10))
    assert not needs_rehash(hash_password("pw"))


def test_insecure_storage_reveals_equal_passwords():
    assert hash_password_insecure("password123") == hash_password_insecure("password123")
    assert hash_password_insecure("password123") == hashlib.sha256(b"password123").hexdigest()
    assert hash_password("password123") != hash_password("password123")


def test_shared_salt_reveals_equal_passwords():
    salt = bcrypt.gensalt(rounds=12)
    a = bcrypt.hashpw(passwords._bcrypt_input("password123"), salt)
    b = bcrypt.hashpw(passwords._bcrypt_input("password123"), salt)
    assert a == b                                    # та сама сіль: повтор пароля видно
    assert hash_password("password123").split("$")[4] != hash_password("password123").split("$")[4]


# ---------- квота спроб у ковзному вікні ----------

def test_lockout_triggers_exactly_at_limit():
    lk = SlidingWindowLockout(max_failures=5, window=900)
    for i in range(4):
        lk.record_attempt("alice", False, T0 + i)
    assert lk.is_allowed("alice", T0 + 4)            # 4 невдачі — ще дозволено
    lk.record_attempt("alice", False, T0 + 4)
    assert not lk.is_allowed("alice", T0 + 5)        # 5-та невдача вичерпала квоту


def test_lockout_window_boundary():
    lk = SlidingWindowLockout(max_failures=5, window=900)
    for i in range(5):
        lk.record_attempt("alice", False, T0 + 60 * i)
    assert lk.retry_after("alice", T0 + 300) == pytest.approx(600)   # час монотонний
    assert not lk.is_allowed("alice", T0 + 899.999)
    assert lk.is_allowed("alice", T0 + 900)          # перша невдача вийшла з вікна
    assert lk.failures("alice", T0 + 900) == 4


def test_lockout_is_sliding_not_fixed():
    lk = SlidingWindowLockout(max_failures=5, window=900)
    for t in (0, 100, 200, 300, 400):
        lk.record_attempt("alice", False, T0 + t)
    assert lk.is_allowed("alice", T0 + 900)          # вийшла невдача t=0
    lk.record_attempt("alice", False, T0 + 900)
    assert not lk.is_allowed("alice", T0 + 901)      # знову 5 у вікні (100..900)


def test_lockout_success_resets_and_accounts_are_independent():
    lk = SlidingWindowLockout(max_failures=5, window=900)
    for i in range(5):
        lk.record_attempt("alice", False, T0 + i)
    assert lk.is_allowed("bob", T0 + 5)
    lk.record_attempt("alice", True, T0 + 6)
    assert lk.is_allowed("alice", T0 + 7)


# ---------- одноразові коди відновлення ----------

def test_ten_codes_generated_with_expected_format():
    codes = generate_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    for c in codes:
        assert len(c) == 11 and c[5] == "-" and all(ch in ALPHABET for ch in c.replace("-", ""))
    assert math.isclose(10 * math.log2(len(ALPHABET)), 50)


def test_code_generation_is_deterministic_with_given_rng():
    seq = iter(range(1000))
    codes = generate_codes(2, randbelow=lambda n: next(seq) % n)
    assert codes == ["01234-56789", "ABCDE-FGHJK"]


def test_each_code_accepted_once_and_count_decreases():
    store, codes = RecoveryCodes.issue("alice")
    for i, c in enumerate(codes):
        assert store.verify_and_consume(c)
        assert store.remaining() == 9 - i
        assert not store.verify_and_consume(c)       # повторне пред'явлення відхилено


def test_wrong_and_foreign_codes_rejected():
    alice, codes = RecoveryCodes.issue("alice")
    bob, _ = RecoveryCodes.issue("bob")
    assert not alice.verify_and_consume("00000-00000")
    assert not bob.verify_and_consume(codes[0])       # хеш прив'язано до облікового запису
    assert alice.remaining() == 10


def test_code_normalization():
    assert normalize(" abcde-fghjk ") == "ABCDEFGHJK"
    assert normalize("o1l1-i") == "01111"
    store = RecoveryCodes("alice", ["0A1B2-C3D4E"])
    assert store.verify_and_consume("oa1b2 c3d4e")


def test_only_hashes_are_stored():
    store, codes = RecoveryCodes.issue("alice")
    stored = " ".join(store._hashes)
    assert all(normalize(c) not in stored for c in codes)
    assert store._hashes[0] == code_hash("alice", codes[0])


# ---------- повний вхід ----------

def test_full_login_with_password_and_code():
    auth = Authenticator()
    codes = auth.register("alice", "Tr0ub4dor&3")
    assert auth.login_password("alice", "Tr0ub4dor&3", T0) is Result.NEED_SECOND_FACTOR
    assert auth.login_code("alice", codes[0], T0 + 1) is Result.OK
    assert auth.remaining_codes("alice") == 9


def test_code_without_password_step_refused():
    auth = Authenticator()
    codes = auth.register("alice", "pw-1")
    assert auth.login_code("alice", codes[0], T0) is Result.NO_PENDING
    assert auth.remaining_codes("alice") == 10


def test_password_and_code_failures_share_quota():
    auth = Authenticator()
    auth.register("alice", "pw-1")
    for i in range(3):
        assert auth.login_password("alice", "wrong", T0 + i) is Result.BAD_CREDENTIALS
    assert auth.login_password("alice", "pw-1", T0 + 3) is Result.NEED_SECOND_FACTOR
    for i in range(2):
        assert auth.login_code("alice", "00000-00000", T0 + 4 + i) is Result.BAD_CODE
    assert auth.login_password("alice", "pw-1", T0 + 10) is Result.LOCKED   # навіть правильний пароль
    assert auth.login_password("alice", "pw-1", T0 + 900) is Result.NEED_SECOND_FACTOR


def test_unknown_account_same_answer_and_counted():
    auth = Authenticator()
    auth.register("alice", "pw-1")
    assert auth.login_password("nobody", "x", T0) is Result.BAD_CREDENTIALS
    assert auth.login_password("alice", "x", T0) is Result.BAD_CREDENTIALS
    assert auth.lockout.failures("nobody", T0) == 1
