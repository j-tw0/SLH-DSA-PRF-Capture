"""Hardware-free layout and SimpleSerial command contract checks."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FW = ROOT / "firmware" / "simpleserial-SLH-DSA"
C = (FW / "slh_dsa_prf_target.c").read_text(encoding="utf-8")
MAKE = (FW / "Makefile").read_text(encoding="utf-8")
HEADER = (FW / "slh_param_config.h").read_text(encoding="ascii")


def main():
    assert "SRC += slh_dsa_prf_target.c" in MAKE
    assert "TARGET = simpleserial-SLH-DSA" in MAKE
    assert "../simpleserial/Makefile.simpleserial" in MAKE
    assert "$(FIRMWAREPATH)/Makefile.inc" in MAKE
    assert "#define SLH_SECURITY_LEVEL 128" in HEADER
    for c, size in (("M", "1"), ("P", "SLH_N"), ("S", "SLH_N"),
                    ("Q", "SLH_N"), ("A", "ADRS_FULL"),
                    ("R", "0"), ("B", "0"), ("N", "0"),
                    ("T", "0"), ("Z", "0")):
        assert f"simpleserial_addcmd('{c}', {size}," in C, c
    assert "trigger_high();" in C and "trigger_low();" in C
    print("PASS: firmware layout and host command contract (static check)")


if __name__ == "__main__":
    main()
