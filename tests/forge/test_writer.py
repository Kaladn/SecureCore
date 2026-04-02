import os
import tempfile
import unittest

from securecore.forge.reader import ForgeReader
from securecore.forge.pulse_writer import ForgePulseWriter, PulseConfig
from securecore.forge.record import ForgeRecord
from securecore.forge.wal import ForgeWAL
from securecore.forge.writer import ForgeWriter
from securecore.substrates.hid import HIDSubstrate


class ForgeWriterTests(unittest.TestCase):
    def test_writer_and_reader_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = ForgeWriter(os.path.join(tmpdir, "ingress"))
            metadata = writer.append_dict(
                {
                    "record_id": "rec_1",
                    "substrate": "ingress",
                    "sequence": 0,
                    "timestamp": "2026-04-01T10:00:00+00:00",
                    "cell_id": "cell_a",
                    "record_type": "request_seen",
                    "payload": {"path": "/.env", "ip": "1.2.3.4"},
                    "chain_hash": "chain_1",
                    "previous_hash": "GENESIS",
                }
            )

            self.assertEqual(metadata["sequence"], 0)

            reader = ForgeReader(os.path.join(tmpdir, "ingress"))
            records = list(reader.iter_records())
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].payload["path"], "/.env")
            self.assertTrue(reader.verify()["intact"])

    def test_recovers_pending_wal_frame(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = os.path.join(tmpdir, "mirror")
            wal = ForgeWAL(os.path.join(base_dir, "records.wal"))
            record = ForgeRecord(
                record_id="rec_2",
                substrate="mirror",
                sequence=1,
                timestamp="2026-04-01T10:00:00+00:00",
                cell_id="cell_b",
                record_type="cell_created",
                payload={"source_ip": "5.6.7.8"},
                chain_hash="chain_2",
                previous_hash="GENESIS",
            )
            wal.append(record.encode())

            writer = ForgeWriter(base_dir)
            self.assertEqual(writer.stats()["count"], 1)
            self.assertEqual(ForgeReader(base_dir).last_record().record_id, "rec_2")

    def test_substrate_dual_write_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            forge_dir = os.path.join(tmpdir, "forge")
            previous_enabled = os.environ.get("SECURECORE_FORGE_ENABLED")
            previous_dir = os.environ.get("SECURECORE_FORGE_DIR")
            try:
                os.environ["SECURECORE_FORGE_ENABLED"] = "true"
                os.environ["SECURECORE_FORGE_DIR"] = forge_dir

                hid = HIDSubstrate(os.path.join(tmpdir, "substrates"))
                hid.record_keyboard_activity(key_event_count=3)

                reader = ForgeReader(os.path.join(forge_dir, "hid"))
                records = list(reader.iter_records())
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].substrate, "hid")
                self.assertEqual(records[0].record_type, "keyboard_activity")
            finally:
                if previous_enabled is None:
                    os.environ.pop("SECURECORE_FORGE_ENABLED", None)
                else:
                    os.environ["SECURECORE_FORGE_ENABLED"] = previous_enabled

                if previous_dir is None:
                    os.environ.pop("SECURECORE_FORGE_DIR", None)
                else:
                    os.environ["SECURECORE_FORGE_DIR"] = previous_dir

    def test_pulse_writer_flushes_batch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = ForgeWriter(os.path.join(tmpdir, "evidence"))
            pulse = ForgePulseWriter(
                writer,
                PulseConfig(max_records_per_pulse=2, max_bytes_per_pulse=10_000, max_age_ms_per_pulse=10_000),
            )

            flushed = pulse.submit(
                {
                    "record_id": "rec_a",
                    "substrate": "evidence",
                    "sequence": 0,
                    "timestamp": "2026-04-01T10:00:00+00:00",
                    "cell_id": "cell_batch",
                    "record_type": "evidence_record",
                    "payload": {"kind": "first"},
                    "chain_hash": "chain_a",
                    "previous_hash": "GENESIS",
                }
            )
            self.assertEqual(flushed, [])

            flushed = pulse.submit(
                {
                    "record_id": "rec_b",
                    "substrate": "evidence",
                    "sequence": 1,
                    "timestamp": "2026-04-01T10:00:01+00:00",
                    "cell_id": "cell_batch",
                    "record_type": "evidence_record",
                    "payload": {"kind": "second"},
                    "chain_hash": "chain_b",
                    "previous_hash": "chain_a",
                }
            )
            self.assertEqual(len(flushed), 2)

            records = list(ForgeReader(os.path.join(tmpdir, "evidence")).iter_records())
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].payload["forge_pulse_id"], 1)
            self.assertEqual(records[1].payload["forge_pulse_id"], 1)


if __name__ == "__main__":
    unittest.main()
