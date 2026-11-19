package dev.localtest.xiaomicloudsync;

import android.accounts.Account;
import android.app.Application;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;

import org.json.JSONObject;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeoutException;

final class PasskeyBridge {
    static final String AUTHORITY = "miui.autofill";
    static final String CLOUD = "com.miui.cloudservice";
    static final String KEYBOX_ACTION = "com.cloud.action.MICLOUD_KEYBOX";
    static final String KEYBOX_DESCRIPTOR = "com.miui.keybox.IMiCloudKeyBoxService";
    static final int TA_VERSION_TRANSACTION = 0x584b01;
    static final Uri FIDO = Uri.parse("content://miui.autofill/fido_credential_summary_record/sync");

    private static final String MARKER = "extensionStr3";
    private static final String[] FIELDS = {"_id", "credentialId", "rpId", "fidoUniqueId", "id", "eTag",
            "status", "localStatus", "modificationTime", MARKER, "spaceVersion", "displayName", "packageName"};
    private static final String UNCHANGED = "_id=? AND localStatus=? AND modificationTime=? AND eTag=? "
            + "AND IFNULL(displayName,'')=? AND IFNULL(packageName,'')=?";
    private static final int CLEAN = -1;
    private static final int UPDATED = 1;
    private static final int DELETED = 2;
    private static final int PURGED = 3;

    private static final String PENDING_ROWS = "((" + MARKER + "=? AND spaceVersion=?) OR ("
            + MARKER + " IS NULL AND id IS NULL)) AND credentialId IS NOT NULL AND credentialId<>'' AND ("
            + "(id IS NULL AND localStatus IN (-1,0,1)) OR (id IS NOT NULL AND (localStatus IN (1,3) OR "
            + "(localStatus=2 AND (status IS NULL OR status NOT IN ('DELETED','PURGED'))))))";

    private static final int MAX_DEFERRED = 16;

    static final class Report {
        int pending, received, uploaded, restored, deleted, conflicts;
        boolean retry, morePages;
    }

    private static final class LocalConflict extends IOException {
        LocalConflict(String message) {
            super(message);
        }
    }

    record Targets(Method account, Method switchEnabled, LegacyPdc pdc, Field keyInfoCreator, Field keyInfoVersion) {}

    private record Local(long row, String credential, String rp, String uniqueKey, String id,
                         long etag, String status, int state, long modified, String owner, long version,
                         String displayName, String packageName) {
        boolean removing() {
            return state == DELETED || state == PURGED;
        }

        boolean hasTombstone() {
            return "DELETED".equals(status) || "PURGED".equals(status);
        }
    }

    private final Application context;
    private final Targets targets;
    private final LegacyPdc pdc;
    private final ContentResolver resolver;
    private final SharedPreferences cursors;

    PasskeyBridge(Application context, Targets targets) {
        this.context = context;
        this.targets = targets;
        pdc = targets.pdc();
        resolver = context.getContentResolver();
        cursors = context.getSharedPreferences("xiaomi_legacy_passkey_cursors", Context.MODE_PRIVATE);
    }

    static Targets resolveTargets(ClassLoader loader, Method account) throws ReflectiveOperationException {
        Method switchEnabled = loader.loadClass("w2.d").getDeclaredMethod("l");
        if (switchEnabled.getReturnType() != boolean.class || !Modifier.isStatic(switchEnabled.getModifiers())) {
            throw new NoSuchMethodException(switchEnabled.toString());
        }
        Class<?> keyInfo = loader.loadClass("com.xiaomi.micloudkeybag.KeyBagKeyInfo");
        Field creator = keyInfo.getField("CREATOR");
        Field version = keyInfo.getDeclaredField("a");
        if (!Modifier.isStatic(creator.getModifiers()) || !Parcelable.Creator.class.isAssignableFrom(creator.getType())
                || Modifier.isStatic(version.getModifiers()) || version.getType() != long.class) {
            throw new NoSuchFieldException(keyInfo.getName() + " parcel format");
        }
        return new Targets(account, switchEnabled, new LegacyPdc(loader), creator, version);
    }

    Report sync(Account account) throws Exception {
        if (account == null || !active(account) || !(Boolean) targets.switchEnabled().invoke(null)) {
            return null;
        }
        long version = installedVersion(account);
        if (version <= 0) {
            Log.i("XiaomiCloudSyncTest", "Legacy passkey sync skipped: MasterKey not installed");
            return null;
        }
        if (version != taVersion()) {
            Log.i("XiaomiCloudSyncTest", "Legacy passkey sync skipped: TEE MasterKey mismatch");
            return null;
        }
        if (version != pdc.masterKeyVersion()) {
            throw new IOException("Legacy MasterKey preflight did not match");
        }
        String owner = accountOwner(account);
        String cursorKey = owner + "-" + version;
        Report report = new Report();
        List<Local> pending = query(PENDING_ROWS, owner, Long.toString(version));
        report.pending = pending.size();
        try (NativePasskeys nativeKeys = new NativePasskeys(context)) {
            for (Local row : pending) {
                requireActive(account);
                try {
                    if (row.removing()) {
                        report.deleted += pushDeletion(account, nativeKeys, row, version);
                    } else {
                        report.uploaded += pushPasskey(account, nativeKeys, row, owner, version);
                    }
                } catch (InterruptedException | RemoteException | TimeoutException failure) {
                    throw failure;
                } catch (LocalConflict conflict) {
                    report.conflicts++;
                } catch (Exception failure) {
                    if (!report.retry) {
                        Log.w("XiaomiCloudSyncTest", "Passkey upload failed: " + failure.getClass().getSimpleName());
                    }
                    report.retry = true;
                }
            }

            long previousTag = cursors.getLong(cursorKey, 0);
            long receivedTag = cursors.getLong(cursorKey + "-max", previousTag);
            String cursor = cursors.getString(cursorKey + "-next", null);
            Set<String> saved = cursors.getStringSet(cursorKey + "-deferred", Set.of());
            Set<String> deferred = new HashSet<>(saved);
            // Retry from the latest cloud revision. Only the record ID is retained on disk.
            for (String id : saved) {
                requireActive(account);
                if (tryPull(account, nativeKeys, id, null, owner, version, report)) {
                    deferred.remove(id);
                }
            }
            boolean canAdvance = true;
            for (int page = 0; page < 10; page++) {
                requireActive(account);
                LegacyPdc.Page changes = pdc.changes(version, previousTag, cursor);
                report.received += changes.records().size();
                for (LegacyPdc.Record record : changes.records()) {
                    requireActive(account);
                    if (!tryPull(account, nativeKeys, record.id(), record, owner, version, report)) {
                        if (deferred.size() < MAX_DEFERRED || deferred.contains(record.id())) {
                            deferred.add(record.id());
                        } else {
                            canAdvance = false;
                        }
                    }
                    receivedTag = Math.max(receivedTag, record.etag());
                }
                requireActive(account);
                String next = changes.nextKey();
                if (canAdvance && (next != null || cursor != null || receivedTag != previousTag || !deferred.equals(saved))) {
                    saveCheckpoint(cursorKey, receivedTag, next, deferred);
                }
                cursor = next;
                if (cursor == null) {
                    break;
                }
                report.morePages = canAdvance && page == 9;
            }
            if (!canAdvance) {
                // Healthy records in this batch were still processed. Replay it from the last safe boundary.
                saveDeferred(cursorKey, deferred);
            }
        }
        return report;
    }

    private boolean tryPull(Account account, NativePasskeys nativeKeys, String id, LegacyPdc.Record record,
                            String owner, long version, Report report) throws Exception {
        try {
            if (record == null) {
                record = pdc.get(id);
                if (!id.equals(record.id())) {
                    throw new IOException("Deferred cloud record identity mismatch");
                }
            }
            if (record.live()) {
                report.restored += pullPasskey(account, nativeKeys, record, owner, version);
            } else {
                report.deleted += pullDeletion(account, nativeKeys, record, owner, version);
            }
            return true;
        } catch (InterruptedException | RemoteException | TimeoutException failure) {
            throw failure;
        } catch (Exception failure) {
            if (!report.retry) {
                Log.w("XiaomiCloudSyncTest", "Passkey download failed: " + failure.getClass().getSimpleName());
            }
            report.retry = true;
            return false;
        }
    }

    private void saveDeferred(String key, Set<String> deferred) throws IOException {
        if (!deferred.equals(cursors.getStringSet(key + "-deferred", Set.of()))
                && !cursors.edit().putStringSet(key + "-deferred", Set.copyOf(deferred)).commit()) {
            throw new IOException("Unable to store deferred cloud records");
        }
    }

    private void saveCheckpoint(String key, long tag, String next, Set<String> deferred) throws IOException {
        SharedPreferences.Editor checkpoint = cursors.edit();
        checkpoint.putStringSet(key + "-deferred", Set.copyOf(deferred));
        if (next == null) {
            checkpoint.putLong(key, tag).remove(key + "-next").remove(key + "-max");
        } else {
            checkpoint.putString(key + "-next", next).putLong(key + "-max", tag);
        }
        if (!checkpoint.commit()) {
            throw new IOException("Unable to store legacy PDC cursor");
        }
    }

    private int pushPasskey(Account account, NativePasskeys nativeKeys, Local row, String owner,
                            long version) throws Exception {
        if (row.state == UPDATED && row.id != null && row.hasTombstone()) {
            return restoreExplicitly(account, nativeKeys, row, owner, version);
        }
        NativePasskeys.Export local = nativeKeys.export(row.credential, version);
        if (local.absent()) {
            return 0;
        }
        if (!local.present()) {
            throw new IOException("Credential could not be exported");
        }
        LegacyPdc.Record remote = null;
        JSONObject candidate = local.content();
        if (row.id != null) {
            remote = pdc.get(row.id);
            verifyLink(row, remote, version);
            if (!row.uniqueKey.equals(candidate.getString("fidoUniqueId"))
                    || !row.rp.equals(candidate.getString("rpId"))) {
                throw new IOException("Linked native passkey changed identity");
            }
            if (!remote.live()) {
                throw new LocalConflict("Cloud deletion intersects a local edit");
            }
            if (remote.etag() < row.etag) {
                throw new IOException("Cloud revision is older than the local checkpoint");
            }
            if (remote.sameCredential(candidate) && sameDisplay(remote.content(), candidate)) {
                saveLive(account, row, remote, owner, version);
                return 0;
            }
            if (remote.etag() != row.etag) {
                throw new LocalConflict("Local and cloud passkey edits overlap");
            }
        }
        requireActive(account);
        if (remote == null) {
            if (!current(row)) {
                throw new IOException("Local passkey changed before recording create");
            }
            rememberCreate(owner, row, candidate, version);
        }
        if (!current(row)) {
            throw new IOException("Local passkey changed before upload");
        }
        LegacyPdc.Receipt receipt = pdc.write(remote, candidate);
        if (receipt.conflict() && remote != null) {
            throw new IOException("Cloud revision changed during upload");
        }
        LegacyPdc.Record confirmed = pdc.get(receipt.record().id());
        if (!receipt.record().id().equals(confirmed.id())) {
            throw new IOException("Cloud readback returned a different record");
        }
        if (!confirmed.live() && receipt.conflict()) {
            throw new LocalConflict("Cloud deletion intersects an unconfirmed create");
        }
        verifyWritten(confirmed, candidate, version);
        if (receipt.conflict() && !sameDisplay(confirmed.content(), candidate)) {
            // A previous create may have reached the cloud before the local row was linked.
            remote = confirmed;
            String originalDisplay = cursors.getString(createKey(owner, row.credential) + "-display", null);
            requireActive(account);
            if (!current(row)) {
                throw new IOException("Local passkey changed during create reconciliation");
            }
            if (displayFingerprint(candidate).equals(originalDisplay)) {
                nativeKeys.restore(confirmed, version);
                saveLive(account, row, confirmed, owner, version);
                return 0;
            }
            if (!displayFingerprint(confirmed.content()).equals(originalDisplay)) {
                throw new LocalConflict("Unconfirmed create has competing display edits");
            }
            receipt = pdc.write(remote, candidate);
            if (receipt.conflict()) {
                throw new IOException("Cloud revision changed during create reconciliation");
            }
            confirmed = pdc.get(remote.id());
            verifyWritten(confirmed, candidate, version);
        }
        if ((!receipt.conflict() && (receipt.record().etag() != confirmed.etag()
                || !candidate.getString("origin").equals(confirmed.content().getString("origin"))))
                || (remote != null && !remote.id().equals(confirmed.id()))) {
            throw new IOException("Legacy passkey write changed before readback");
        }
        if (!sameDisplay(confirmed.content(), candidate)) {
            throw new IOException("Cloud did not confirm passkey display fields");
        }
        saveLive(account, row, confirmed, owner, version);
        return receipt.conflict() ? 0 : 1;
    }

    private int restoreExplicitly(Account account, NativePasskeys nativeKeys, Local row,
                                  String owner, long version) throws Exception {
        LegacyPdc.Record remote = pdc.get(row.id);
        verifyLink(row, remote, version);
        if (!remote.live()) {
            requireActive(account);
            if (remote.etag() != row.etag) {
                throw new LocalConflict("Pending local restore conflicts with cloud revision");
            }
            if (!current(row)) {
                throw new IOException("Local passkey changed before restore");
            }
            if (pdc.restore(remote).conflict()) {
                throw new IOException("Legacy passkey restore conflict");
            }
            remote = pdc.get(row.id);
            verifyLink(row, remote, version);
        }
        if (!remote.live()) {
            throw new IOException("Legacy passkey restore could not be verified");
        }
        return pullPasskey(account, nativeKeys, remote, owner, version);
    }

    private int pushDeletion(Account account, NativePasskeys nativeKeys, Local row, long version) throws Exception {
        LegacyPdc.Record remote = pdc.get(row.id);
        verifyLink(row, remote, version);
        if (remote.live()) {
            requireActive(account);
            if (remote.etag() != row.etag) {
                throw new LocalConflict("Pending local deletion conflicts with cloud revision");
            }
            if (!current(row)) {
                throw new IOException("Local passkey changed before cloud deletion");
            }
            LegacyPdc.Receipt result = pdc.delete(remote);
            if (result.conflict()) {
                throw new IOException("Legacy passkey deletion conflict");
            }
            remote = pdc.get(remote.id());
            verifyLink(row, remote, version);
        }
        if (remote.live()) {
            throw new IOException("Legacy passkey deletion could not be verified");
        }
        deleteNative(account, nativeKeys, row, version);
        saveTombstone(account, row, remote);
        return 1;
    }

    private int pullPasskey(Account account, NativePasskeys nativeKeys, LegacyPdc.Record remote,
                            String owner, long version) throws Exception {
        NativePasskeys.validate(remote.content(), version);
        if (!remote.uniqueKey().equals(remote.content().getString("fidoUniqueId"))) {
            throw new IOException("Legacy passkey cloud identity mismatch");
        }
        Local row = single("credentialId=?", remote.credentialId());
        String createdLocally = cursors.getString(createKey(owner, remote.credentialId()), null);
        if (createdLocally != null && createdLocally.equals(version + ":" + remote.uniqueKey())
                && (row == null || (row.id == null && row.removing()))) {
            if (row != null || cursors.getBoolean(removedKey(owner, remote.credentialId()), false)) {
                requireActive(account);
                LegacyPdc.Record latest = pdc.get(remote.id());
                if (latest.live() && latest.etag() == remote.etag() && latest.sameCredential(remote.content())
                        && (row == null || current(row)) && !pdc.delete(latest).conflict()) {
                    LegacyPdc.Record deleted = pdc.get(latest.id());
                    if (!deleted.live() && latest.uniqueKey().equals(deleted.uniqueKey())) {
                        forgetCreate(owner, remote.credentialId(), version, remote.uniqueKey());
                        return 0;
                    }
                }
            }
            // The upload may have reached the cloud before the local create was reconciled.
            throw new IOException("Unresolved local create or removal");
        }
        if (row != null) {
            if (!eligible(row, owner, version) || (row.id != null && !row.id.equals(remote.id()))) {
                return 0;
            }
            if (row.id != null && row.etag >= remote.etag()) {
                if (createdLocally != null && remote.uniqueKey().equals(row.uniqueKey)) {
                    forgetCreate(owner, row.credential, version, remote.uniqueKey());
                }
                return 0;
            }
            // The upload scan revisits pending edits and deletions, even after the pull cursor advances.
            if (row.state == PURGED || (row.state == DELETED && !row.hasTombstone())
                    || (row.state == UPDATED && !row.hasTombstone())) {
                return 0;
            }
        }
        NativePasskeys.Export existing = nativeKeys.export(remote.credentialId(), version);
        if (existing.present() && !remote.sameCredential(existing.content())) {
            throw new IOException("Local and cloud passkey identities differ");
        }
        if (!existing.present() && !existing.absent()) {
            throw new IOException("Unable to check native credential presence");
        }
        boolean needsImport = !existing.present() || !sameDisplay(remote.content(), existing.content());
        if (needsImport && row != null && row.id == null && createdLocally != null && existing.present()) {
            return 0;
        }
        if (needsImport) {
            requireActive(account);
            LegacyPdc.Record latest = pdc.get(remote.id());
            if (!latest.live() || latest.etag() != remote.etag() || !latest.sameCredential(remote.content())) {
                throw new IOException("Legacy passkey changed before import");
            }
            requireActive(account);
            if (row == null ? single("credentialId=?", remote.credentialId()) != null : !current(row)) {
                throw new IOException("Local passkey changed during pull");
            }
            nativeKeys.restore(latest, version);
        }
        saveLive(account, row, remote, owner, version);
        return needsImport ? 1 : 0;
    }

    private int pullDeletion(Account account, NativePasskeys nativeKeys, LegacyPdc.Record remote,
                             String owner, long version) throws Exception {
        Local row = single(MARKER + "=? AND id=?", owner, remote.id());
        if (row == null) {
            String credential = remote.credentialId();
            if (!credential.isEmpty() && (version + ":" + remote.uniqueKey())
                    .equals(cursors.getString(createKey(owner, credential), null))) {
                Local unlinked = single("credentialId=?", credential);
                boolean removed = unlinked == null ? cursors.getBoolean(removedKey(owner, credential), false)
                        : unlinked.id == null && eligible(unlinked, owner, version) && unlinked.removing();
                if (!removed) {
                    throw new IOException("Cloud deletion intersects an unconfirmed local create");
                }
                LegacyPdc.Record latest = pdc.get(remote.id());
                if (latest.live() || latest.etag() != remote.etag() || !latest.uniqueKey().equals(remote.uniqueKey())) {
                    throw new IOException("Cloud removal changed during reconciliation");
                }
                requireActive(account);
                forgetCreate(owner, credential, version, remote.uniqueKey());
            }
            return 0;
        }
        if (!eligible(row, owner, version) || row.etag >= remote.etag()) {
            return 0;
        }
        if (row.state == UPDATED) {
            // The linked dirty row keeps this conflict visible to the next upload scan.
            return 0;
        }
        verifyLink(row, remote, version);
        requireActive(account);
        LegacyPdc.Record latest = pdc.get(remote.id());
        verifyLink(row, latest, version);
        if (latest.live() || latest.etag() != remote.etag()) {
            throw new IOException("Cloud passkey changed before native deletion");
        }
        if (!current(row)) {
            throw new IOException("Local passkey changed during deletion");
        }
        deleteNative(account, nativeKeys, row, version);
        saveTombstone(account, row, latest);
        return 1;
    }

    private void deleteNative(Account account, NativePasskeys nativeKeys, Local row, long version) throws Exception {
        NativePasskeys.Export existing = nativeKeys.export(row.credential, version);
        if (existing.absent()) {
            return;
        }
        if (!existing.present() || !row.uniqueKey.equals(existing.content().getString("fidoUniqueId"))
                || !row.rp.equals(existing.content().getString("rpId"))) {
            throw new IOException("Local passkey deletion identity check failed");
        }
        requireActive(account);
        if (!current(row)) {
            throw new IOException("Local passkey changed during deletion");
        }
        nativeKeys.delete(row.credential, row.rp);
        if (!nativeKeys.export(row.credential, version).absent()) {
            throw new IOException("Native passkey removal could not be verified");
        }
    }

    private void saveLive(Account account, Local row, LegacyPdc.Record record, String owner, long version)
            throws Exception {
        requireActive(account);
        ContentValues values = new ContentValues();
        values.put(MARKER, owner);
        values.put("id", record.id());
        values.put("eTag", record.etag());
        values.put("status", "NORMAL");
        values.put("credentialId", record.credentialId());
        values.put("fidoUniqueId", record.uniqueKey());
        values.put("rpId", record.content().getString("rpId"));
        values.put("displayName", record.content().optString("displayName"));
        values.put("packageName", record.content().optString("packageName"));
        values.put("spaceVersion", version);
        values.put("exchangeStatus", 0);
        values.put("retryTimes", 0);
        values.put("localStatus", CLEAN);
        if (row == null) {
            if (single("credentialId=?", record.credentialId()) != null) {
                throw new IOException("Local passkey appeared during restore");
            }
            values.put("accountUUID", java.util.UUID.randomUUID().toString());
            values.put("creationTime", record.created());
            values.put("modificationTime", record.modified());
            values.put("lastUsedTime", 0);
            if (resolver.insert(FIDO, values) == null) {
                throw new IOException("Unable to register restored passkey");
            }
        } else {
            updateIfUnchanged(row, values);
        }
        forgetCreate(owner, record.credentialId(), version, record.uniqueKey());
    }

    private void saveTombstone(Account account, Local row, LegacyPdc.Record record) throws Exception {
        requireActive(account);
        if (row.state == PURGED) {
            if (resolver.delete(FIDO, UNCHANGED, rowSelection(row)) != 1) {
                throw new IOException("Local passkey changed during purge");
            }
            return;
        }
        ContentValues values = new ContentValues();
        values.put("eTag", record.etag());
        values.put("status", "purged".equals(record.status()) ? "PURGED" : "DELETED");
        values.put("localStatus", DELETED);
        updateIfUnchanged(row, values);
    }

    private void updateIfUnchanged(Local row, ContentValues values) throws IOException {
        if (resolver.update(FIDO, values, UNCHANGED, rowSelection(row)) != 1) {
            throw new IOException("Local passkey changed during reconciliation");
        }
    }

    private static String[] rowSelection(Local row) {
        return new String[]{Long.toString(row.row), Integer.toString(row.state),
                Long.toString(row.modified), Long.toString(row.etag),
                row.displayName == null ? "" : row.displayName, row.packageName == null ? "" : row.packageName};
    }

    private List<Local> query(String where, String... args) throws IOException {
        ArrayList<Local> records = new ArrayList<>();
        try (Cursor cursor = resolver.query(FIDO, FIELDS, where, args, "_id")) {
            if (cursor == null) {
                throw new IOException("Local passkey provider unavailable");
            }
            while (cursor.moveToNext()) {
                records.add(new Local(cursor.getLong(0), cursor.getString(1), cursor.getString(2),
                        cursor.getString(3), cursor.getString(4), cursor.getLong(5), cursor.getString(6),
                        cursor.getInt(7), cursor.getLong(8), cursor.getString(9), cursor.getLong(10),
                        cursor.getString(11), cursor.getString(12)));
            }
        }
        return records;
    }

    private Local single(String where, String... args) throws IOException {
        List<Local> rows = query(where, args);
        if (rows.size() > 1) {
            throw new IOException("Ambiguous local passkey identity");
        }
        return rows.isEmpty() ? null : rows.get(0);
    }

    private boolean current(Local row) throws IOException {
        return row.equals(single("_id=?", Long.toString(row.row)));
    }

    private static boolean eligible(Local row, String owner, long version) {
        return row.credential != null && !row.credential.isEmpty()
                && ((owner.equals(row.owner) && row.version == version)
                        || (row.owner == null && row.id == null));
    }

    private static void verifyLink(Local row, LegacyPdc.Record remote, long version) throws Exception {
        if (!row.id.equals(remote.id()) || !row.uniqueKey.equals(remote.uniqueKey())) {
            throw new IOException("Legacy passkey record link mismatch");
        }
        if (remote.live() || !remote.credentialId().isEmpty()) {
            NativePasskeys.validate(remote.content(), version);
            if (!row.credential.equals(remote.credentialId()) || !row.rp.equals(remote.content().getString("rpId"))) {
                throw new IOException("Legacy passkey linked credential mismatch");
            }
        }
    }

    private static void verifyWritten(LegacyPdc.Record record, JSONObject expected, long version) throws Exception {
        if (!record.live() || !record.sameCredential(expected)) {
            throw new IOException("Legacy passkey write could not be verified");
        }
        NativePasskeys.validate(record.content(), version);
    }

    private static boolean sameDisplay(JSONObject left, JSONObject right) {
        return left.optString("displayName").equals(right.optString("displayName"))
                && left.optString("packageName").equals(right.optString("packageName"));
    }

    private static String displayFingerprint(JSONObject content) throws Exception {
        String name = content.optString("displayName");
        return digest(name.length() + ":" + name + content.optString("packageName"));
    }

    private long installedVersion(Account account) throws Exception {
        Parcelable.Creator<?> creator = (Parcelable.Creator<?>) targets.keyInfoCreator().get(null);
        try (BoundService service = new BoundService(context, "com.miui.cloudservice.MICLOUD_KEYBAG", CLOUD)) {
            IBinder binder = service.binder();
            Parcel data = Parcel.obtain(binder);
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken("com.xiaomi.micloudkeybag.IMiCloudKeyBagService");
                data.writeTypedObject(account, 0);
                if (!binder.transact(4, data, reply, 0)) {
                    throw new IOException("Legacy installed MasterKey lookup unavailable");
                }
                reply.readException();
                Object installed = reply.readTypedObject(creator);
                return installed == null ? 0 : targets.keyInfoVersion().getLong(installed);
            } finally {
                data.recycle();
                reply.recycle();
            }
        }
    }

    private long taVersion() throws Exception {
        try (BoundService service = new BoundService(context, KEYBOX_ACTION, CLOUD)) {
            IBinder binder = service.binder();
            Parcel data = Parcel.obtain(binder);
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(KEYBOX_DESCRIPTOR);
                if (!binder.transact(TA_VERSION_TRANSACTION, data, reply, 0)) {
                    throw new IOException("Signed KeyBox version service unavailable");
                }
                reply.readException();
                return reply.readLong();
            } finally {
                data.recycle();
                reply.recycle();
            }
        }
    }

    private boolean active(Account account) throws Exception {
        return account.equals(targets.account().invoke(null, context)) && ContentResolver.getMasterSyncAutomatically()
                && ContentResolver.getSyncAutomatically(account, AUTHORITY);
    }

    private void requireActive(Account account) throws Exception {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("Legacy passkey sync interrupted");
        }
        if (!active(account)) {
            throw new IOException("Legacy passkey sync cancelled");
        }
    }

    private void forgetCreate(String owner, String credential, long version, String uniqueKey) throws Exception {
        String key = createKey(owner, credential);
        if ((version + ":" + uniqueKey).equals(cursors.getString(key, null))
                && !cursors.edit().remove(key).remove(key + "-display").remove(removedKey(owner, credential)).commit()) {
            throw new IOException("Unable to clear confirmed cloud create");
        }
    }

    private void rememberCreate(String owner, Local row, JSONObject candidate, long version) throws Exception {
        String key = createKey(owner, row.credential);
        String unique = version + ":" + candidate.getString("fidoUniqueId");
        String existing = cursors.getString(key, null);
        if (existing != null && !existing.equals(unique)) {
            throw new IOException("Pending create identity changed");
        }
        if (existing == null && !cursors.edit().putString(key, unique)
                .putString(key + "-display", displayFingerprint(candidate)).commit()) {
            throw new IOException("Unable to persist pending cloud create");
        }
    }

    static void noteNativeRemoval(Context context, Account account, List<String> credentials) throws Exception {
        String owner = accountOwner(account);
        SharedPreferences state = context.getSharedPreferences("xiaomi_legacy_passkey_cursors", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = state.edit();
        boolean updated = false;
        for (String credential : credentials) {
            if (credential != null && state.contains(createKey(owner, credential))) {
                editor.putBoolean(removedKey(owner, credential), true);
                updated = true;
            }
        }
        if (updated && !editor.commit()) {
            throw new IOException("Unable to record native removal");
        }
    }

    private static String createKey(String owner, String credential) throws Exception {
        return owner + "-create-" + digest(credential);
    }

    private static String removedKey(String owner, String credential) throws Exception {
        return owner + "-removed-" + digest(credential);
    }

    private static String accountOwner(Account account) throws Exception {
        return "legacy11-" + digest(account.type + "\n" + account.name);
    }

    private static String digest(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    static Bundle syncExtras() {
        Bundle extras = new Bundle();
        extras.putString("syncType", "fidoChanged");
        extras.putBoolean("xiaomiLegacyPasskeyBridge", true);
        return extras;
    }
}
