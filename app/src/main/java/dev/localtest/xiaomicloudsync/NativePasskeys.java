package dev.localtest.xiaomicloudsync;

import android.content.Context;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

final class NativePasskeys implements AutoCloseable {
    private static final String INTERFACE = "org.fidoalliance.aidl.IFIDOPasskey";
    private static final String CALLBACK = "org.fidoalliance.aidl.PasskeyCallback";
    private static final String EXPORT_CALLBACK = "org.fidoalliance.aidl.PasskeyExportCallback";
    private static final int IMPORT = 1;
    private static final int EXPORT = 2;
    private static final int DELETE = 3;

    private record Result(int status, List<String> entries) {}

    record Export(int status, boolean missing, JSONObject content) {
        boolean present() {
            return status == 0 && content != null;
        }

        boolean absent() {
            return missing;
        }
    }

    private final Context context;
    private BoundService service;

    NativePasskeys(Context context) {
        this.context = context;
    }

    Export export(String credential, long version) throws Exception {
        Result result = call(EXPORT, credential);
        if (result.status != 0 || result.entries.size() != 1) {
            throw new IOException("Native passkey export failed");
        }
        JSONObject entry = new JSONObject(result.entries.get(0));
        if (!credential.equals(entry.getString("credentialId"))) {
            throw new IOException("Native passkey export identity mismatch");
        }
        int status = entry.getInt("status");
        if (status != 0) {
            // ASM adds 256 to CTAP status codes and also uses 4 for missing IDs in a valid batch.
            String message = entry.optString("message");
            boolean missing = status == 256 + 0x2e || (status == 4 && message.isEmpty());
            return new Export(status, missing, null);
        }
        JSONObject content = new JSONObject();
        for (String field : List.of("rpId", "fidoUniqueId", "credentialId", "origin", "displayName")) {
            content.put(field, entry.getString(field));
        }
        content.put("packageName", entry.optString("packageName"));
        content.put("spaceVersion", version);
        validate(content, version);
        return new Export(0, false, content);
    }

    void restore(LegacyPdc.Record record, long version) throws Exception {
        validate(record.content(), version);
        Result imported = call(IMPORT, record.content().getString("origin"));
        Export after = export(record.credentialId(), version);
        if (imported.status != 0 || !after.present() || !record.sameCredential(after.content)) {
            throw new IOException("Native passkey import could not be verified");
        }
    }

    void delete(String credential, String rp) throws Exception {
        String selection = new JSONObject().put("rpID", rp).put("credential", credential).toString();
        if (call(DELETE, selection).status != 0) {
            throw new IOException("Native passkey deletion failed");
        }
    }

    static void validate(JSONObject content, long version) throws Exception {
        if (content == null || content.getLong("spaceVersion") != version
                || content.getString("credentialId").isEmpty() || content.getString("rpId").isEmpty()
                || content.getString("fidoUniqueId").isEmpty()) {
            throw new IOException("Legacy passkey identity or MasterKey mismatch");
        }
        JSONObject origin = new JSONObject(content.getString("origin"));
        if (!content.getString("credentialId").equals(origin.getString("credential"))
                || !content.getString("rpId").equals(origin.getString("rpID"))
                || origin.getString("keyHandle").isEmpty()) {
            throw new IOException("Native passkey envelope identity mismatch");
        }
    }

    private Result call(int transaction, String argument) throws Exception {
        boolean exporting = transaction == EXPORT;
        String callbackDescriptor = exporting ? EXPORT_CALLBACK : CALLBACK;
        CompletableFuture<Result> result = new CompletableFuture<>();
        List<String> entries = new ArrayList<>();
        Binder callback = new Binder() {
            @Override
            protected synchronized boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code != FIRST_CALL_TRANSACTION) {
                    return super.onTransact(code, data, reply, flags);
                }
                data.enforceInterface(callbackDescriptor);
                int status = data.readInt();
                if (exporting) {
                    List<String> chunk = data.createStringArrayList();
                    if (chunk != null) {
                        entries.addAll(chunk);
                    }
                }
                if (status != 240) {
                    result.complete(new Result(status, List.copyOf(entries)));
                }
                reply.writeNoException();
                return true;
            }
        };
        callback.attachInterface(null, callbackDescriptor);
        if (service == null) {
            service = new BoundService(context, "org.fidoalliance.aidl.service.PASSKEY_OPERATION", "com.fido.asm");
        }
        IBinder binder = service.binder();
        Parcel request = Parcel.obtain(binder);
        try {
            request.writeInterfaceToken(INTERFACE);
            request.writeStringList(List.of(argument));
            request.writeStrongBinder(callback);
            if (!binder.transact(transaction, request, null, IBinder.FLAG_ONEWAY)) {
                throw new RemoteException("Native passkey transaction failed");
            }
            return result.get(20, TimeUnit.SECONDS);
        } finally {
            request.recycle();
        }
    }

    @Override
    public void close() {
        if (service != null) {
            service.close();
        }
    }
}
