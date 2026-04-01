"""SecureCore Forge.

Forge is the pre-cutover binary storage foundation for SecureCore.
It is introduced beside the current JSONL truth stores, not as an
immediate replacement for them.

Current doctrine:
- substrates append
- forge stores
- loggers log
- agents infer
"""

from securecore.forge.reader import ForgeReader
from securecore.forge.pulse_writer import ForgePulseWriter, PulseConfig
from securecore.forge.record import ForgeRecord
from securecore.forge.writer import ForgeWriter

__all__ = [
    "ForgePulseWriter",
    "ForgeReader",
    "ForgeRecord",
    "ForgeWriter",
    "PulseConfig",
]
