from __future__ import annotations

import time

import pytest

from loglens.detect import detect, sliding_windows
from loglens.parsers import Event


def auth_fail(ip="1.2.3.4", user="root", ts=1000.0):
    return Event(ts=ts, kind="auth", raw="", ip=ip, user=user, failed=True)


def web_hit(ip, path="/", status=200, ts=1000.0, method="GET"):
    return Event(ts=ts, kind="web", raw="", ip=ip, status=status,
                 path=path, method=method, failed=status >= 400)


class TestSlidingWindows:
    def test_single_burst(self):
        tss = [0, 1, 2, 3]
        assert list(sliding_windows(tss, 10)) == [(0, 4)]

    def test_split_by_gap(self):
        tss = [0, 1, 2, 100, 101]
        assert list(sliding_windows(tss, 10)) == [(0, 3), (3, 5)]


class TestBruteForce:
    def test_burst_detected(self):
        evs = [auth_fail(ts=1000 + i) for i in range(6)]
        out = [f for f in detect(evs) if f.rule == "brute_force"]
        assert len(out) == 1
        f = out[0]
        assert f.severity == "high" and f.ip == "1.2.3.4" and f.count == 6

    def test_below_threshold_ignored(self):
        evs = [auth_fail() for _ in range(3)]
        assert not [f for f in detect(evs) if f.rule == "brute_force"]

    def test_spread_over_hours_not_detected(self):
        # 8 fails but 1 per 20 min → outside the default window
        evs = [auth_fail(ts=i * 1200) for i in range(8)]
        assert not [f for f in detect(evs) if f.rule == "brute_force"]

    def test_successes_dont_count(self):
        ok = Event(ts=1000, kind="auth", raw="", ip="9.9.9.9", user="ana")
        evs = [ok] * 10
        assert not [f for f in detect(evs) if f.rule == "brute_force"]


class TestUserSpray:
    def test_many_users_one_ip(self):
        evs = [auth_fail(user=f"user{i}", ts=1000 + i) for i in range(6)]
        out = [f for f in detect(evs) if f.rule == "user_spray"]
        assert len(out) == 1 and out[0].count == 6

    def test_few_users_not_flagged(self):
        evs = [auth_fail(user="root"), auth_fail(user="root", ts=1001)]
        assert not [f for f in detect(evs) if f.rule == "user_spray"]


class TestWebScan:
    def test_scan_detected(self):
        probe_paths = ["/admin", "/.env", "/wp-login.php", "/backup",
                       "/config", "/db", "/old", "/test"]
        evs = []
        for i in range(24):
            evs.append(web_hit("5.5.5.5", path=probe_paths[i % len(probe_paths)],
                               status=404 if i % 3 else 403, ts=1000 + i))
        out = [f for f in detect(evs) if f.rule == "web_scan"]
        assert len(out) == 1
        assert out[0].count >= 20 and out[0].severity == "high"

    def test_normal_browsing_ok(self):
        evs = [web_hit("7.7.7.7", path=f"/page/{i}", status=200, ts=1000 + i)
               for i in range(50)]
        assert not [f for f in detect(evs) if f.rule == "web_scan"]


class TestErrorSpike:
    def test_spike_detected_and_capped(self):
        evs = [web_hit(f"10.0.0.{i % 250}", path="/api", status=500,
                       ts=2000 + i / 10) for i in range(40)]
        out = [f for f in detect(evs) if f.rule == "error_spike"]
        assert 1 <= len(out) <= 3 and out[0].count >= 15

    def test_no_spike_on_200s(self):
        evs = [web_hit("10.0.0.1", status=200, ts=2000 + i) for i in range(30)]
        assert not [f for f in detect(evs) if f.rule == "error_spike"]


class TestSuspiciousPaths:
    @pytest.mark.parametrize("path", ["/.env", "/.git/config", "/etc/passwd",
                                      "/wp-login.php", "/../../etc/shadow"])
    def test_flags_probe(self, path):
        evs = [web_hit("8.8.8.8", path=path, status=200)]
        assert any(f.rule == "suspicious_path" for f in detect(evs))

    def test_clean_path_not_flagged(self):
        evs = [web_hit("8.8.8.8", path="/blog/post-1")]
        assert not any(f.rule == "suspicious_path" for f in detect(evs))

    def test_counts_repeat_probes(self):
        evs = [web_hit("8.8.8.8", path="/.env", ts=1000 + i) for i in range(3)]
        out = [f for f in detect(evs) if f.rule == "suspicious_path"]
        assert len(out) == 1 and out[0].count == 3
