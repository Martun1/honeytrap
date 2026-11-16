import asyncio, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import honeytrap as h


class TestFingerprint(unittest.TestCase):
    def names(self, data):
        return [a["name"] for a in h.fingerprint(data, "http")]

    def test_log4shell(self):
        self.assertIn("Log4Shell (CVE-2021-44228)", self.names(b"${jndi:ldap://x/a}"))

    def test_sqli(self):
        self.assertIn("SQL injection", self.names(b"id=1 UNION SELECT a,b FROM users--"))

    def test_traversal(self):
        self.assertIn("path traversal", self.names(b"GET /../../etc/passwd"))

    def test_scanner(self):
        self.assertIn("scanner tool", self.names(b"User-Agent: sqlmap/1.8"))

    def test_clean(self):
        self.assertEqual(self.names(b"GET / HTTP/1.1\r\nHost: example.com\r\n"), [])

    def test_redis_rce(self):
        self.assertIn("Redis unauth RCE attempt", [a["name"] for a in h.fingerprint(b"CONFIG SET dir /var/spool/cron", "redis")])


class TestRecord(unittest.TestCase):
    def test_demo_records_and_dedups_ips(self):
        stats = h.Stats()
        h.C.off()
        h.run_demo(stats, quiet=True)
        self.assertEqual(len(stats.events), len(h.DEMO_ATTACKS))
        self.assertEqual(len(stats.by_ip), 7)
        self.assertGreaterEqual(stats.by_alert["default/weak credentials"], 2)
        self.assertTrue(any("root:root" in c for c in stats.credentials))
        # no User-Agent noise in credentials
        self.assertFalse(any("agent" in c.lower() for c in stats.credentials))

    def test_live_connection_logged(self):
        async def run():
            stats = h.Stats()
            ht = h.Honeytrap(stats, quiet=True)
            srv = await asyncio.start_server(ht.handle(0, h.DECOYS[80]), "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"GET /.env HTTP/1.1\r\n\r\n"); await w.drain()
            await asyncio.sleep(0.2); w.close()
            await asyncio.sleep(0.2); srv.close()
            return stats
        stats = asyncio.run(run())
        self.assertGreaterEqual(len(stats.events), 1)
        self.assertEqual(stats.events[0].service, "http")


if __name__ == "__main__":
    unittest.main()
