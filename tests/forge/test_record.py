import unittest

from securecore.forge.record import ForgeRecord


class ForgeRecordTests(unittest.TestCase):
    def test_round_trip(self):
        record = ForgeRecord(
            record_id="abc123",
            substrate="ingress",
            sequence=7,
            timestamp="2026-04-01T10:00:00+00:00",
            cell_id="cell_1",
            record_type="request_seen",
            payload={"ip": "1.2.3.4", "path": "/.env"},
            chain_hash="chain",
            previous_hash="prev",
        )

        encoded = record.encode()
        decoded = ForgeRecord.decode(encoded)

        self.assertEqual(decoded.record_id, record.record_id)
        self.assertEqual(decoded.substrate, record.substrate)
        self.assertEqual(decoded.sequence, record.sequence)
        self.assertEqual(decoded.payload, record.payload)


if __name__ == "__main__":
    unittest.main()
