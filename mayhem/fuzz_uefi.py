#!/usr/bin/env python3
"""Atheris fuzz harness for uefi-firmware-parser.

Drives the two public entry points of the library on arbitrary bytes:
  * uefi_firmware.AutoParser  — auto-detects the firmware container type and parses it
    (UEFI volumes, Intel ME, Dell PFS, flash descriptors, ... — the bulk of the parser).
  * uefi_firmware.efi_compressor.LzmaDecompress — the bundled C extension's LZMA path.

Atheris instruments the imported uefi_firmware Python modules (coverage), so libFuzzer drives
the parser toward new code paths. Run modes (driven by the compiled launcher `fuzz_uefi` /
`fuzz_uefi-standalone`):
  * fuzzing      — `python3 fuzz_uefi.py [libFuzzer args]`
  * single input — `python3 fuzz_uefi.py <file>` (libFuzzer runs it once)
"""
import resource
import sys

import atheris

import fuzz_helpers

# The parser amplifies tiny malformed inputs into unbounded allocations (e.g. an Intel ME "$FPT"
# size field is read as a length and used to size buffers), driving RSS past multiple GB on a
# single 30-byte input. Without a cap libFuzzer kills the whole process on the first such input
# (out-of-memory) and the run never reaches its time budget — so coverage never grows. Cap the
# process address space so a runaway allocation raises a *catchable* MemoryError instead; normal
# parsing uses ~50 MB, so this ceiling only bites the pathological inputs.
_AS_LIMIT = 1536 * 1024 * 1024  # 1.5 GiB
try:
    _soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
    _new_hard = _hard if _hard != resource.RLIM_INFINITY and _hard < _AS_LIMIT else _AS_LIMIT
    resource.setrlimit(resource.RLIMIT_AS, (_AS_LIMIT, _new_hard))
except (ValueError, OSError):
    pass

# Instrument the library under test so the fuzzer gets coverage feedback. A bare
# instrument_imports() (no include=) instruments uefi_firmware *and every pure-python module it
# pulls in at import time*, so all parser submodules reached here are covered — and nothing the
# harness needs has been imported (and thus module-cached uninstrumented) before this block. The
# bundled C extension (efi_compressor) is native code and is not bytecode-instrumented, but
# importing it here keeps the decompress path exercised below.
with atheris.instrument_imports():
    import uefi_firmware
    from uefi_firmware import efi_compressor

# This backport reproduces mayhemheroes/uefi-firmware-parser fuzz-uefi run 2, whose original harness
# (fork commit a1a5a1ab2ff6) caught only the decompressor's generic exception, letting every other
# exception the parser raised propagate as a finding. The live harness (mayhem branch) later widened
# this to a broad EXPECTED_PARSE_EXCEPTIONS allowlist that swallows exactly the "Uncaught Exception"
# classes (CWE-248) the original run found — restored to the original's narrower catch here so this
# frozen backport reproduces them instead of silently discarding them.


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
            comp_buff = efi_compressor.LzmaDecompress(buff, len(buff))
            efi_compressor.LzmaDecompress(comp_buff, len(comp_buff))
    except Exception as e:
        # The decompressor (native ext) raises a generic exception on malformed/incompressible
        # input — expected, keep fuzzing. Anything else propagates as a genuine finding, matching
        # the original run's harness.
        if 'decompress' in str(e):
            return -1
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
