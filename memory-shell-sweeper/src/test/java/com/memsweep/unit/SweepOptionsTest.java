package com.memsweep.unit;

import com.memsweep.core.SweepOptions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SweepOptionsTest {

    @Test
    void parse_nullArgs_returnsDefaults() {
        SweepOptions o = SweepOptions.parse(null);
        assertEquals(SweepOptions.Mode.SCAN, o.getMode());
        assertTrue(o.isBytecodeScan());
        assertEquals(3000, o.getGracePeriodMs());
        assertTrue(o.getTargetIds().isEmpty());
    }

    @Test
    void parse_fullArgs() {
        SweepOptions o = SweepOptions.parse(
                "mode=remove;bytecodeScan=false;ids=a,b;graceMs=5000;dumpDir=/tmp/x");
        assertEquals(SweepOptions.Mode.REMOVE, o.getMode());
        assertFalse(o.isBytecodeScan());
        assertEquals(List.of("a", "b"), o.getTargetIds());
        assertEquals(5000, o.getGracePeriodMs());
        assertEquals("/tmp/x", o.getDumpDir());
    }

    @Test
    void parse_ignoresMalformedPairs() {
        SweepOptions o = SweepOptions.parse("garbage;mode=dry-run;;");
        assertEquals(SweepOptions.Mode.DRY_RUN, o.getMode());
    }
}
