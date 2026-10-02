package com.fusepir.demo;


import com.fusepir.bff.*;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON writer, the mirror of {@link CapeDemoData.JsonParser}.
 *
 * <p>Exists so the demo service needs no JSON dependency: the only JSON-capable jar
 * on this lab's classpath is guava, which does not do JSON, and adding a jar for a
 * handful of response objects is not worth the classpath churn.
 */
public final class Json {

    private Json() {
    }

    public static String write(Object o) {
        StringBuilder sb = new StringBuilder();
        writeTo(sb, o);
        return sb.toString();
    }

    private static void writeTo(StringBuilder sb, Object o) {
        if (o == null) {
            sb.append("null");
        } else if (o instanceof String) {
            escape(sb, (String) o);
        } else if (o instanceof Boolean || o instanceof Number) {
            sb.append(o.toString());
        } else if (o instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                escape(sb, String.valueOf(e.getKey()));
                sb.append(':');
                writeTo(sb, e.getValue());
            }
            sb.append('}');
        } else if (o instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object e : (List<?>) o) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeTo(sb, e);
            }
            sb.append(']');
        } else if (o instanceof int[]) {
            sb.append('[');
            int[] a = (int[]) o;
            for (int i = 0; i < a.length; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(a[i]);
            }
            sb.append(']');
        } else if (o instanceof long[]) {
            sb.append('[');
            long[] a = (long[]) o;
            for (int i = 0; i < a.length; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(a[i]);
            }
            sb.append(']');
        } else {
            escape(sb, o.toString());
        }
    }

    private static void escape(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
