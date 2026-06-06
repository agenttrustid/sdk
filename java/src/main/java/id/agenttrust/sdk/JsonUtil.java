package id.agenttrust.sdk;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Lightweight JSON serializer and parser for the AgentTrust ID SDK.
 * <p>
 * Handles strings, numbers (int, long, double), booleans, null, arrays, and
 * nested objects. No external dependencies are required.
 * <p>
 * This class is not intended for general-purpose JSON handling. It covers the
 * simple, shallow JSON structures used by the AgentTrust ID REST API.
 */
public final class JsonUtil {

    private JsonUtil() {
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /**
     * Serializes a {@code Map<String, Object>} to a JSON string.
     */
    public static String serialize(Map<String, Object> map) {
        if (map == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        serializeMap(map, sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void serializeValue(Object value, StringBuilder sb) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String) {
            sb.append('"');
            escapeString((String) value, sb);
            sb.append('"');
        } else if (value instanceof Boolean) {
            sb.append(value.toString());
        } else if (value instanceof Number) {
            Number num = (Number) value;
            if (value instanceof Double || value instanceof Float) {
                double d = num.doubleValue();
                if (d == Math.floor(d) && !Double.isInfinite(d) && d <= Long.MAX_VALUE && d >= Long.MIN_VALUE) {
                    // Emit integer-looking doubles without the decimal part
                    sb.append((long) d);
                } else {
                    sb.append(d);
                }
            } else {
                sb.append(num.toString());
            }
        } else if (value instanceof Map) {
            serializeMap((Map<String, Object>) value, sb);
        } else if (value instanceof List) {
            serializeList((List<Object>) value, sb);
        } else {
            // Fall back to toString wrapped in quotes
            sb.append('"');
            escapeString(value.toString(), sb);
            sb.append('"');
        }
    }

    private static void serializeMap(Map<String, Object> map, StringBuilder sb) {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"');
            escapeString(entry.getKey(), sb);
            sb.append('"');
            sb.append(':');
            serializeValue(entry.getValue(), sb);
        }
        sb.append('}');
    }

    private static void serializeList(List<Object> list, StringBuilder sb) {
        sb.append('[');
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            serializeValue(list.get(i), sb);
        }
        sb.append(']');
    }

    private static void escapeString(String s, StringBuilder sb) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Parsing
    // -----------------------------------------------------------------------

    /**
     * Parses a JSON string into a {@code Map<String, Object>}.
     *
     * @throws IllegalArgumentException if the input is not valid JSON or is not a JSON object
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parse(String json) {
        if (json == null || json.trim().isEmpty()) {
            return new LinkedHashMap<>();
        }
        Parser parser = new Parser(json.trim());
        Object result = parser.parseValue();
        if (result instanceof Map) {
            return (Map<String, Object>) result;
        }
        throw new IllegalArgumentException("Expected JSON object at root level");
    }

    /**
     * Parses a JSON string and returns the raw value (could be Map, List,
     * String, Number, Boolean, or null).
     */
    public static Object parseValue(String json) {
        if (json == null || json.trim().isEmpty()) {
            return null;
        }
        Parser parser = new Parser(json.trim());
        return parser.parseValue();
    }

    // -----------------------------------------------------------------------
    // Recursive descent parser
    // -----------------------------------------------------------------------

    private static final class Parser {
        private final String input;
        private int pos;

        Parser(String input) {
            this.input = input;
            this.pos = 0;
        }

        Object parseValue() {
            skipWhitespace();
            if (pos >= input.length()) {
                throw new IllegalArgumentException("Unexpected end of input");
            }
            char c = input.charAt(pos);
            switch (c) {
                case '{':
                    return parseObject();
                case '[':
                    return parseArray();
                case '"':
                    return parseString();
                case 't':
                case 'f':
                    return parseBoolean();
                case 'n':
                    return parseNull();
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return parseNumber();
                    }
                    throw new IllegalArgumentException(
                            "Unexpected character '" + c + "' at position " + pos);
            }
        }

        private Map<String, Object> parseObject() {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (pos < input.length() && input.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                if (pos >= input.length()) {
                    throw new IllegalArgumentException("Unterminated object");
                }
                if (input.charAt(pos) == '}') {
                    pos++;
                    return map;
                }
                expect(',');
            }
        }

        private List<Object> parseArray() {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (pos < input.length() && input.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                if (pos >= input.length()) {
                    throw new IllegalArgumentException("Unterminated array");
                }
                if (input.charAt(pos) == ']') {
                    pos++;
                    return list;
                }
                expect(',');
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < input.length()) {
                char c = input.charAt(pos);
                if (c == '"') {
                    pos++;
                    return sb.toString();
                }
                if (c == '\\') {
                    pos++;
                    if (pos >= input.length()) {
                        throw new IllegalArgumentException("Unterminated string escape");
                    }
                    char esc = input.charAt(pos);
                    switch (esc) {
                        case '"':
                            sb.append('"');
                            break;
                        case '\\':
                            sb.append('\\');
                            break;
                        case '/':
                            sb.append('/');
                            break;
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'b':
                            sb.append('\b');
                            break;
                        case 'f':
                            sb.append('\f');
                            break;
                        case 'u':
                            if (pos + 4 >= input.length()) {
                                throw new IllegalArgumentException("Incomplete unicode escape");
                            }
                            String hex = input.substring(pos + 1, pos + 5);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                            break;
                        default:
                            throw new IllegalArgumentException(
                                    "Invalid escape character: \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
                pos++;
            }
            throw new IllegalArgumentException("Unterminated string");
        }

        private Number parseNumber() {
            int start = pos;
            if (pos < input.length() && input.charAt(pos) == '-') {
                pos++;
            }
            while (pos < input.length() && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') {
                pos++;
            }
            boolean isFloating = false;
            if (pos < input.length() && input.charAt(pos) == '.') {
                isFloating = true;
                pos++;
                while (pos < input.length() && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') {
                    pos++;
                }
            }
            if (pos < input.length() && (input.charAt(pos) == 'e' || input.charAt(pos) == 'E')) {
                isFloating = true;
                pos++;
                if (pos < input.length() && (input.charAt(pos) == '+' || input.charAt(pos) == '-')) {
                    pos++;
                }
                while (pos < input.length() && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') {
                    pos++;
                }
            }
            String numStr = input.substring(start, pos);
            if (isFloating) {
                return Double.parseDouble(numStr);
            }
            try {
                long val = Long.parseLong(numStr);
                if (val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE) {
                    return (int) val;
                }
                return val;
            } catch (NumberFormatException e) {
                return Double.parseDouble(numStr);
            }
        }

        private Boolean parseBoolean() {
            if (input.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (input.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new IllegalArgumentException("Expected boolean at position " + pos);
        }

        private Object parseNull() {
            if (input.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new IllegalArgumentException("Expected null at position " + pos);
        }

        private void expect(char expected) {
            skipWhitespace();
            if (pos >= input.length() || input.charAt(pos) != expected) {
                throw new IllegalArgumentException(
                        "Expected '" + expected + "' at position " + pos);
            }
            pos++;
        }

        private void skipWhitespace() {
            while (pos < input.length()) {
                char c = input.charAt(pos);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    break;
                }
                pos++;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Convenience helpers
    // -----------------------------------------------------------------------

    /** Returns the value for the given key as a String, or {@code defaultValue} if absent/null. */
    public static String getString(Map<String, Object> map, String key, String defaultValue) {
        Object v = map.get(key);
        return v != null ? v.toString() : defaultValue;
    }

    /** Returns the value for the given key as a String, or null if absent/null. */
    public static String getString(Map<String, Object> map, String key) {
        return getString(map, key, null);
    }

    /** Returns the value for the given key as a boolean, or {@code defaultValue} if absent/null. */
    public static boolean getBoolean(Map<String, Object> map, String key, boolean defaultValue) {
        Object v = map.get(key);
        if (v instanceof Boolean) {
            return (Boolean) v;
        }
        return defaultValue;
    }

    /** Returns the value for the given key as an int, or {@code defaultValue} if absent/null. */
    public static int getInt(Map<String, Object> map, String key, int defaultValue) {
        Object v = map.get(key);
        if (v instanceof Number) {
            return ((Number) v).intValue();
        }
        return defaultValue;
    }

    /** Returns the value for the given key as a Double, or null if absent/null. */
    public static Double getDouble(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof Number) {
            return ((Number) v).doubleValue();
        }
        return null;
    }

    /** Returns the value for the given key as an Integer, or null if absent/null. */
    public static Integer getInteger(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof Number) {
            return ((Number) v).intValue();
        }
        return null;
    }

    /** Returns the value for the given key as a {@code List<String>}, or an empty list if absent. */
    @SuppressWarnings("unchecked")
    public static List<String> getStringList(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof List) {
            List<String> result = new ArrayList<>();
            for (Object item : (List<Object>) v) {
                result.add(item != null ? item.toString() : null);
            }
            return result;
        }
        return new ArrayList<>();
    }

    /** Returns the value for the given key as a {@code Map<String, Object>}, or null if absent. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> getMap(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof Map) {
            return (Map<String, Object>) v;
        }
        return null;
    }

    /** Parses an ISO 8601 / RFC 3339 timestamp; returns null on empty/invalid input. */
    public static Instant parseInstant(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(s);
        } catch (Exception e) {
            try {
                return Instant.parse(s.replace("+00:00", "Z"));
            } catch (Exception e2) {
                return null;
            }
        }
    }
}
