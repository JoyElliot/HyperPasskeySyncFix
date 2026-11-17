package dev.localtest.xiaomicloudsync;

import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

final class LegacyPdc {
    private static final String RECORDS =
            "https://pdc.micloud.xiaomi.net/mic/pdc/v4.1/apps/miuiautofill/spaces/default/records";

    record Page(List<Record> records, String nextKey) {}
    record Receipt(Record record, boolean conflict) {}

    record Record(String id, String uniqueKey, long etag, String status, JSONObject content,
                  long created, long modified) {
        boolean live() {
            return "normal".equals(status);
        }

        String credentialId() {
            return content == null ? "" : content.optString("credentialId");
        }

        boolean sameCredential(JSONObject other) {
            return uniqueKey.equals(other.optString("fidoUniqueId"))
                    && credentialId().equals(other.optString("credentialId"))
                    && content != null && content.optString("rpId").equals(other.optString("rpId"));
        }
    }

    private final Method request;
    private final Field success;
    private final Field data;

    LegacyPdc(ClassLoader loader) throws ReflectiveOperationException {
        request = loader.loadClass("d7.g").getDeclaredMethod("I", String.class, HashMap.class, boolean.class);
        Class<?> response = loader.loadClass("O3.a");
        success = response.getDeclaredField("a");
        data = response.getDeclaredField("f");
        if (!Modifier.isStatic(request.getModifiers()) || !response.isAssignableFrom(request.getReturnType())) {
            throw new NoSuchMethodException(request.toString());
        }
        if (success.getType() != boolean.class || data.getType().isPrimitive()) {
            throw new NoSuchFieldException(response.getName() + " result fields");
        }
    }

    long masterKeyVersion() throws Exception {
        JSONObject reply = index("B", bound(Long.MAX_VALUE, Long.MAX_VALUE), bound(0, 0), true, 1);
        JSONArray records = reply.getJSONArray("records");
        if (records.length() == 0) {
            return 0;
        }
        JSONObject version = records.getJSONObject(0);
        if (!"spaceVersion".equals(version.getString("type"))
                || !"normal".equals(version.getString("status"))) {
            return 0;
        }
        return version.getJSONObject("contentJson").getLong("spaceVersion");
    }

    Page changes(long version, long previousTag, String cursor) throws Exception {
        String begin = cursor == null ? bound(previousTag + 1, version) : cursor;
        JSONObject reply = index("C", begin, bound(Long.MAX_VALUE, version), false, 200);
        JSONArray entries = reply.getJSONArray("records");
        List<Record> records = new ArrayList<>(entries.length());
        for (int i = 0; i < entries.length(); i++) {
            records.add(parse(entries.getJSONObject(i)));
        }
        String next = reply.getBoolean("hasMore") ? reply.getString("beginKey") : null;
        if (next != null && (next.isEmpty() || next.equals(begin))) {
            throw new IOException("Legacy PDC cursor did not advance");
        }
        return new Page(records, next);
    }

    Record get(String id) throws Exception {
        return parse(send(path(id), new HashMap<>(), true).getJSONObject("record"));
    }

    Receipt write(Record current, JSONObject passkey) throws Exception {
        JSONObject record = new JSONObject().put("type", "fido").put("status", "normal")
                .put("uniqueKey", passkey.getString("fidoUniqueId")).put("contentJson", passkey);
        HashMap<String, String> fields = new HashMap<>();
        if (current != null) {
            record.put("id", current.id);
            fields.put("eTag", Long.toString(current.etag));
        }
        fields.put("record", record.toString());
        String url = current == null ? RECORDS : path(current.id) + "/update";
        return receipt(send(url, fields, false));
    }

    Receipt delete(Record current) throws Exception {
        return changeStatus(current, "delete");
    }

    Receipt restore(Record current) throws Exception {
        return changeStatus(current, "restore");
    }

    private Receipt changeStatus(Record current, String operation) throws Exception {
        HashMap<String, String> fields = new HashMap<>();
        fields.put("type", "fido");
        fields.put("id", current.id);
        fields.put("eTag", Long.toString(current.etag));
        return receipt(send(path(current.id) + "/" + operation, fields, false));
    }

    private JSONObject index(String name, String begin, String end, boolean reverse, int limit)
            throws Exception {
        HashMap<String, String> fields = new HashMap<>();
        fields.put("indexName", name);
        fields.put("beginKey", begin);
        fields.put("endKey", end);
        fields.put("isReverse", Boolean.toString(reverse));
        fields.put("limit", Integer.toString(limit));
        return send(RECORDS + "/index", fields, true);
    }

    private JSONObject send(String url, HashMap<String, String> fields, boolean get) throws Exception {
        Object reply = request.invoke(null, url, fields, get);
        if (!success.getBoolean(reply) || !(data.get(reply) instanceof JSONObject body)) {
            throw new IOException("Legacy PDC request failed");
        }
        return body;
    }

    private static String bound(long etag, long version) throws Exception {
        return new JSONObject().put("_eTag", etag).put("spaceVersion", version).toString();
    }

    private static String path(String id) {
        return RECORDS + "/" + Uri.encode(id);
    }

    private static Receipt receipt(JSONObject body) throws Exception {
        return switch (body.getString("conflictType")) {
            case "none" -> new Receipt(parse(body.getJSONObject("record")), false);
            case "eTag", "id", "uniqueKey" -> new Receipt(parse(body.getJSONObject("conflictRecord")), true);
            default -> throw new IOException("Unexpected legacy PDC receipt");
        };
    }

    private static Record parse(JSONObject object) throws Exception {
        String id = object.getString("id");
        String uniqueKey = object.optString("uniqueKey");
        String status = object.getString("status");
        long etag = object.getLong("eTag");
        if (!"fido".equals(object.getString("type")) || id.isEmpty() || etag <= 0
                || !List.of("normal", "deleted", "purged").contains(status)) {
            throw new IOException("Unexpected legacy passkey record");
        }
        return new Record(id, uniqueKey, etag, status, object.optJSONObject("contentJson"),
                object.optLong("creationTime", 0), object.optLong("modificationTime", 0));
    }
}
