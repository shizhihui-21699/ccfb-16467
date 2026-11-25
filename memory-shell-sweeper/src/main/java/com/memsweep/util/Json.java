package com.memsweep.util;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/** 极简 JSON 序列化器，零依赖，只支持 Map/Collection/数组/包装类型/String/null。 */
public final class Json {

    private Json() {}

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder(1024);
        writeValue(sb, value);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String || value instanceof Character) {
            writeString(sb, value.toString());
        } else if (value instanceof Number || value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map<?, ?> map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                writeValue(sb, e.getValue());
            }
            sb.append('}');
        } else if (value instanceof Collection<?> col) {
            sb.append('[');
            boolean first = true;
            for (Object o : col) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeValue(sb, o);
            }
            sb.append(']');
        } else if (value.getClass().isArray()) {
            sb.append('[');
            int n = java.lang.reflect.Array.getLength(value);
            for (int i = 0; i < n; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                writeValue(sb, java.lang.reflect.Array.get(value, i));
            }
            sb.append(']');
        } else {
            writeString(sb, String.valueOf(value));
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    /** 方便构造有序 JSON 对象。 */
    public static Map<String, Object> obj() {
        return new LinkedHashMap<>();
    }
}
