package com.memsweep.unit;

import com.memsweep.util.Json;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonTest {

    @Test
    void writesNestedStructure() {
        Map<String, Object> m = Json.obj();
        m.put("a", 1);
        m.put("b", List.of("x", "y"));
        m.put("c", Map.of("k", true));
        m.put("d", null);
        String json = Json.write(m);
        assertTrue(json.contains("\"a\":1"));
        assertTrue(json.contains("\"b\":[\"x\",\"y\"]"));
        assertTrue(json.contains("\"k\":true"));
        assertTrue(json.contains("\"d\":null"));
    }

    @Test
    void escapesSpecialCharacters() {
        String json = Json.write(Map.of("q", "a\"b\\c\nd"));
        assertTrue(json.contains("\\\""));
        assertTrue(json.contains("\\\\"));
        assertTrue(json.contains("\\n"));
    }

    @Test
    void handlesArraysAndPrimitives() {
        String json = Json.write(new int[]{1, 2, 3});
        assertEquals("[1,2,3]", json);
        assertEquals("true", Json.write(Boolean.TRUE));
        assertEquals("\"s\"", Json.write("s"));
    }
}
