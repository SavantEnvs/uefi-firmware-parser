#!/usr/bin/env python3
"""Atheris fuzz harness for uefi-firmware-parser — ported from the mayhemheroes fork at the
commit this run was built from (2c3ee8cb7ea86141afd1ca3fe14c347613baf12f), unmodified. The
current (live) v2 harness added a broad exception allowlist and an RLIMIT_AS cap that swallow
the very defects this backport reproduces (uncaught exceptions, unbounded allocation), so this
file restores the original behavior rather than reusing the live one verbatim (BACKPORT.md,
"Input-interface caveat").

Drives the two public entry points of the library on arbitrary bytes:
  * uefi_firmware.AutoParser  — auto-detects the firmware container type and parses it.
  * uefi_firmware.efi_compressor.LzmaDecompress — the bundled C extension's LZMA path.

Run modes (driven by the compiled launcher `fuzz_uefi` / `fuzz_uefi-standalone`):
  * fuzzing      — `python3 fuzz_uefi.py [libFuzzer args]`
  * single input — `python3 fuzz_uefi.py <file>` (libFuzzer runs it once)
"""
import sys

import atheris

import fuzz_helpers

with atheris.instrument_imports(include=["uefi_firmware"]):
    import uefi_firmware


@atheris.instrument_func
def TestOneInput(data):
    if len(data) < 20:
        return -1
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        if fdp.ConsumeBool():
            parser = uefi_firmware.AutoParser(fdp.ConsumeRemainingBytes())
            if parser.type() != 'unknown':
                parser.parse()
        else:
            buff = fdp.ConsumeRemainingBytes()
            comp_buff = uefi_firmware.efi_compressor.LzmaDecompress(
                    buff, len(buff))
            decomp_buff = uefi_firmware.efi_compressor.LzmaDecompress(
                    comp_buff, len(comp_buff))
    except Exception as e:
        if 'decompress' in str(e):
            return -1
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
