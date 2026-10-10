import datetime as dt
import sys
import types
import unittest

import logwatch


class ClaudePromptBudgetTests(unittest.TestCase):
    def test_compact_summary_drops_unbounded_client_map(self):
        summary = {
            "client_class": {f"198.51.100.{i}": "bot" for i in range(5000)},
            "top_clients": [("198.51.100.1", 12)],
            "health": {"gaps": [f"gap-{i}" for i in range(100)]},
        }
        compact = logwatch._claude_summary(summary)
        self.assertNotIn("client_class", compact)
        self.assertEqual(compact["top_clients"], [["198.51.100.1", 12, "bot"]])
        self.assertEqual(len(compact["health"]["gaps"]), 20)

    def test_log_excerpt_clips_individual_lines_and_total_budget(self):
        lines = [("x" * 10000) + str(i) for i in range(100)]
        excerpt, included = logwatch._bounded_log_excerpt(lines, 12000)
        self.assertLessEqual(len(excerpt), 12000)
        self.assertLess(included, len(lines))
        self.assertIn("omitted by Claude prompt budget", excerpt)
        self.assertIn("truncated", excerpt)

    def test_claude_request_stays_inside_hard_budget(self):
        captured = {}

        class FakeMessages:
            def create(self, **kwargs):
                captured.update(kwargs)
                return types.SimpleNamespace(
                    content=[types.SimpleNamespace(type="text", text="STATUS: ALL CLEAR")]
                )

        class FakeAnthropicClient:
            def __init__(self):
                self.messages = FakeMessages()

        fake_module = types.SimpleNamespace(Anthropic=FakeAnthropicClient)
        old_module = sys.modules.get("anthropic")
        old_budget = logwatch.CLAUDE_MAX_INPUT_CHARS
        old_line_budget = logwatch.CLAUDE_MAX_LOG_LINE_CHARS
        try:
            sys.modules["anthropic"] = fake_module
            logwatch.CLAUDE_MAX_INPUT_CHARS = 20000
            logwatch.CLAUDE_MAX_LOG_LINE_CHARS = 500
            summary = {
                "client_class": {f"203.0.113.{i}": "bot" for i in range(10000)},
                "top_clients": [("203.0.113.1", 100)],
                "health": {"gaps": [f"gap-{i}" for i in range(500)]},
                "non_json_samples": ["e" * 10000 for _ in range(20)],
                "top_paths": [("GET /" + "p" * 10000, 20)],
                "top_user_agents": [("ua" * 5000, 10)],
                "spoofed_crawlers": [],
                "probes": [("203.0.113.1", "/" + "x" * 10000, 404)] * 50,
                "probe_ips": [("203.0.113.1", 50)],
                "slow_requests": [("/" + "s" * 10000, 900)] * 20,
                "api_key_prefixes": [str(i) for i in range(1000)],
            }
            kept = [("k" * 20000) + str(i) for i in range(1500)]
            start = dt.datetime(2026, 10, 9, tzinfo=dt.timezone.utc)
            end = start + dt.timedelta(days=1)
            result = logwatch.claude_report(
                {"status": "running"}, summary, {"requests": 1},
                [("WARN", "test")], [], kept, start, end,
            )
            self.assertEqual(result, "STATUS: ALL CLEAR")
            body = captured["messages"][0]["content"]
            self.assertLessEqual(len(body), 20000)
            self.assertIn("Today's metrics", body)
            self.assertIn("prompt hard-truncated by logwatch", body)
            self.assertNotIn("203.0.113.9999", body)
        finally:
            logwatch.CLAUDE_MAX_INPUT_CHARS = old_budget
            logwatch.CLAUDE_MAX_LOG_LINE_CHARS = old_line_budget
            if old_module is None:
                sys.modules.pop("anthropic", None)
            else:
                sys.modules["anthropic"] = old_module


if __name__ == "__main__":
    unittest.main()
