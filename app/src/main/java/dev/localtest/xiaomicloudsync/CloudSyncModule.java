package dev.localtest.xiaomicloudsync;

import android.accounts.Account;
import android.app.Application;
import android.content.ContentProviderClient;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.SyncResult;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Parcel;
import android.util.Log;

import io.github.libxposed.api.XposedModule;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicBoolean;

public final class CloudSyncModule extends XposedModule {
    private static final String TAG = "XiaomiCloudSyncTest";
    private static final String PASSWORDS = "com.miui.passwords";
    private static final String CLOUD = PasskeyBridge.CLOUD;
    private static final String FIDO_ASM = "com.fido.asm";
    private static final String CLOUD_SHA256 =
            "6203237113ac354f01f97acb6ffe4fb1f995fefc6fc11ad1f6e23d1f39999832";
    private static final String PASSWORDS_SHA256 =
            "021e11b6f6626d72a339da1e223f7276f55ae8c25893e1c4e7cf557327e23dc0";
    private static final String FIDO_CALLBACK = "com.miui.credential.ICredentialPassService";

    private final AtomicBoolean gateLogged = new AtomicBoolean();
    private final AtomicBoolean syncRequested = new AtomicBoolean();
    private record ScheduledSync(Account account, SyncResult result) {}

    private final ThreadLocal<ScheduledSync> stockSync = new ThreadLocal<>();
    private final ThreadLocal<Account> legacyAccount = new ThreadLocal<>();

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!param.isFirstPackage() || !"marble".equals(Build.DEVICE)
                || !"OS4.0.6.0.XPCCNXM".equals(Build.VERSION.INCREMENTAL)) {
            return;
        }

        try {
            String process = Application.getProcessName();
            String name = param.getPackageName();
            ClassLoader loader = param.getClassLoader();
            String apk = param.getApplicationInfo().sourceDir;
            if (CLOUD.equals(name) && CLOUD.equals(process) && matchesApk(apk, CLOUD_SHA256)) {
                registerCloudGate(loader);
                registerVersionReader(loader);
            }
            if (PASSWORDS.equals(name) && matchesApk(apk, PASSWORDS_SHA256)) {
                if ((PASSWORDS + ":sync").equals(process)) {
                    registerPasskeySync(loader);
                    registerNativeEvents(loader);
                } else if (PASSWORDS.equals(process)) {
                    registerScheduling(loader);
                }
            }
        } catch (Exception | LinkageError failure) {
            logFailure("Module setup", failure);
        }
    }

    private void registerCloudGate(ClassLoader loader) throws ReflectiveOperationException {
        Class<?> appKeys = loader.loadClass("B2.a");
        Method supportsFido = appKeys.getDeclaredMethod("e");
        if (supportsFido.getReturnType() != boolean.class) {
            throw new NoSuchMethodException("Unexpected FIDO support method");
        }

        deoptimize(appKeys.getDeclaredMethod("f", Context.class));
        Class<?> passwordSync = loader.loadClass("y2.a");
        deoptimize(passwordSync.getDeclaredMethod("g", Context.class, String.class));
        hook(supportsFido).intercept(chain -> {
            if (gateLogged.compareAndSet(false, true)) {
                log(Log.INFO, TAG, "Skipped modern FIDO initialization in CloudService");
            }
            return false;
        });
        log(Log.INFO, TAG, "Password sync gate registered");
    }

    private void registerVersionReader(ClassLoader loader) throws ReflectiveOperationException {
        Class<?> stub = loader.loadClass(PasskeyBridge.KEYBOX_DESCRIPTOR + "$Stub");
        Method onTransact = stub.getDeclaredMethod("onTransact", int.class, Parcel.class, Parcel.class, int.class);
        Method cloudApp = loader.loadClass(CLOUD + ".CloudApp").getDeclaredMethod("g");
        Method account = xiaomiAccount(loader);
        Method nativeService = loader.loadClass("R1.g").getDeclaredMethod("e");
        Method nativeVersion = loader.loadClass("vendor.xiaomi.hardware.mikeybag.IMiKeyBagService")
                .getMethod("getMasterKeyVersion", String.class);
        hook(onTransact).intercept(chain -> {
            if ((Integer) chain.getArg(0) != PasskeyBridge.TA_VERSION_TRANSACTION) {
                return chain.proceed();
            }
            Parcel input = (Parcel) chain.getArg(1);
            Parcel reply = (Parcel) chain.getArg(2);
            Context app = (Context) cloudApp.invoke(null);
            int caller = Binder.getCallingUid();
            if (reply == null || !callerIs(app, caller, PASSWORDS)
                    || app.getPackageManager().checkSignatures(android.os.Process.myUid(), caller)
                            != PackageManager.SIGNATURE_MATCH) {
                throw new SecurityException("Unauthorized KeyBox version request");
            }
            input.enforceInterface(PasskeyBridge.KEYBOX_DESCRIPTOR);
            input.enforceNoDataAvail();
            long identity = Binder.clearCallingIdentity();
            long version = 0;
            try {
                Account current = (Account) account.invoke(null, app);
                if (current != null) {
                    Object hardware = nativeService.invoke(null);
                    if (hardware != null) {
                        version = (Long) nativeVersion.invoke(hardware, current.name);
                    }
                }
            } catch (Exception | LinkageError failure) {
                logFailure("KeyBox version read", failure);
            } finally {
                Binder.restoreCallingIdentity(identity);
            }
            reply.writeNoException();
            reply.writeLong(version);
            return true;
        });
        log(Log.INFO, TAG, "Legacy TA version reader registered");
    }

    private void registerPasskeySync(ClassLoader loader) throws ReflectiveOperationException {
        Method onPerformSync = loader.loadClass("T3.e").getDeclaredMethod("onPerformSync",
                Account.class, Bundle.class, String.class, ContentProviderClient.class, SyncResult.class);
        hook(onPerformSync).intercept(chain -> {
            stockSync.set(new ScheduledSync((Account) chain.getArg(0), (SyncResult) chain.getArg(4)));
            try {
                return chain.proceed();
            } finally {
                stockSync.remove();
            }
        });
        Class<?> fidoSync = loader.loadClass("O2.e");
        Method accountLookup = xiaomiAccount(loader);
        hook(accountLookup).intercept(chain -> {
            Object current = chain.proceed();
            Account expected = legacyAccount.get();
            if (expected != null && !expected.equals(current)) {
                throw new SecurityException("Xiaomi account changed during passkey sync");
            }
            return current;
        });
        Class<?> requestEnvironment = loader.loadClass("Q2.a");
        deoptimize(requestEnvironment.getDeclaredMethod("w"));
        deoptimize(requestEnvironment.getDeclaredMethod("z"));
        Method cloudEnvironment = loader.loadClass("R3.c").getDeclaredMethod("b");
        Field environmentBuilder = requestEnvironment.getDeclaredField("b");
        Field tokenProvider = loader.loadClass("X3.a").getDeclaredField("b");
        Field cache = loader.loadClass("M4.h").getDeclaredField("b");
        deoptimize(loader.loadClass("P2.d").getDeclaredMethod("d", Bundle.class));
        deoptimize(loader.loadClass("Q2.a").getDeclaredMethod("t"));
        hook(fidoSync.getDeclaredMethod("c")).intercept(chain -> {
            ScheduledSync run = stockSync.get();
            if (run != null && run.account != null && run.result != null) {
                SyncResult frameworkResult = run.result;
                try {
                    Object builder = environmentBuilder.get(cloudEnvironment.invoke(null));
                    @SuppressWarnings("unchecked")
                    ThreadLocal<Object> requestToken = (ThreadLocal<Object>) cache.get(tokenProvider.get(builder));
                    Object stockToken = requestToken.get();
                    PasskeyBridge.Report report;
                    legacyAccount.set(run.account);
                    requestToken.remove();
                    try {
                        PasskeyBridge bridge = new PasskeyBridge(passwordsApp(loader), loader);
                        report = bridge.sync(run.account);
                    } finally {
                        legacyAccount.remove();
                        requestToken.remove();
                        if (stockToken != null) {
                            requestToken.set(stockToken);
                        }
                    }
                    if (report != null) {
                        log(Log.INFO, TAG, "Legacy passkey sync uploaded=" + report.uploaded()
                                + " restored=" + report.restored() + " deleted=" + report.deleted()
                                + " retry=" + report.retry());
                        frameworkResult.moreRecordsToGet |= report.morePages();
                        if (report.retry()) {
                            frameworkResult.stats.numIoExceptions++;
                        }
                    }
                } catch (Exception | LinkageError failure) {
                    frameworkResult.stats.numIoExceptions++;
                    logFailure("Legacy passkey sync", failure);
                }
            }
            return null;
        });
        // The phone's KeyBag ABI cannot service the modern FIDO sync path.
        // These three methods belong to FIDO only; the Passwords adapter remains native.
        hook(fidoSync.getDeclaredMethod("b")).intercept(chain -> null);
        hook(fidoSync.getDeclaredMethod("e")).intercept(chain -> null);
        log(Log.INFO, TAG, "Legacy passkey SyncAdapter registered");
    }

    private void registerNativeEvents(ClassLoader loader) throws ReflectiveOperationException {
        Class<?> binder = loader.loadClass("O2.a");
        hook(binder.getDeclaredMethod("onTransact", int.class, Parcel.class, Parcel.class, int.class))
                .intercept(chain -> {
                    if ((Integer) chain.getArg(0) != 1 || !(chain.getThisObject() instanceof Binder instance)
                            || !FIDO_CALLBACK.equals(instance.getInterfaceDescriptor())) {
                        return chain.proceed();
                    }
                    Application app;
                    try {
                        app = passwordsApp(loader);
                        if (!callerIs(app, Binder.getCallingUid(), FIDO_ASM)) {
                            return chain.proceed();
                        }
                        noteNativeRemoval(app, loader, (Parcel) chain.getArg(1));
                    } catch (Exception failure) {
                        logFailure("Native passkey event", failure);
                        return chain.proceed();
                    }
                    Object result = chain.proceed();
                    if (Boolean.TRUE.equals(result)) {
                        requestSoon(app, loader);
                    }
                    return result;
                });
    }

    private static void noteNativeRemoval(Application app, ClassLoader loader, Parcel original) throws Exception {
        Parcel payload = Parcel.obtain();
        try {
            payload.appendFrom(original, 0, original.dataSize());
            payload.setDataPosition(original.dataPosition());
            payload.enforceInterface(FIDO_CALLBACK);
            if (payload.readByte() != 3) {
                return;
            }
            ArrayList<String> credentials = payload.createStringArrayList();
            Account account = (Account) xiaomiAccount(loader).invoke(null, app);
            if (account != null && credentials != null && !credentials.isEmpty()) {
                PasskeyBridge.noteNativeRemoval(app, account, credentials);
            }
        } finally {
            payload.recycle();
        }
    }

    private void registerScheduling(ClassLoader loader) throws ReflectiveOperationException {
        Class<?> app = loader.loadClass(PASSWORDS + ".PasswordsApp");
        hook(app.getDeclaredMethod("onCreate")).intercept(chain -> {
            Object result = chain.proceed();
            requestSoon((Application) chain.getThisObject(), loader);
            return result;
        });
        Class<?> provider = loader.loadClass(PASSWORDS + ".datacenter.db.PrivacyDataProvider");
        Method update = provider.getDeclaredMethod("update", Uri.class, ContentValues.class, String.class, String[].class);
        hook(update).intercept(chain -> {
            Object result = chain.proceed();
            Uri uri = (Uri) chain.getArg(0);
            ContentValues values = (ContentValues) chain.getArg(1);
            if (result instanceof Integer count && count > 0 && uri != null && values != null
                    && "content://miui.autofill/fido_credential_summary_record".equals(uri.toString())
                    && values.containsKey("localStatus")) {
                try {
                    requestSoon(passwordsApp(loader), loader);
                } catch (Exception failure) {
                    logFailure("Passkey management change", failure);
                }
            }
            return result;
        });
    }

    private void requestSoon(Application app, ClassLoader loader) {
        if (app == null || !syncRequested.compareAndSet(false, true)) {
            return;
        }
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            syncRequested.set(false);
            try {
                Account current = (Account) xiaomiAccount(loader).invoke(null, app);
                if (current != null && ContentResolver.getMasterSyncAutomatically()
                        && ContentResolver.getSyncAutomatically(current, PasskeyBridge.AUTHORITY)) {
                    Bundle extras = PasskeyBridge.syncExtras();
                    ContentResolver.addPeriodicSync(current, PasskeyBridge.AUTHORITY, extras, 15 * 60L);
                    ContentResolver.requestSync(current, PasskeyBridge.AUTHORITY, extras);
                }
            } catch (Exception | LinkageError failure) {
                logFailure("Legacy passkey scheduling", failure);
            }
        }, 1500);
    }

    private static boolean callerIs(Context app, int uid, String packageName) throws PackageManager.NameNotFoundException {
        return app != null && app.getPackageManager().getPackageUid(packageName, 0) == uid;
    }

    private static Method xiaomiAccount(ClassLoader loader) throws ReflectiveOperationException {
        return loader.loadClass("miui.accounts.ExtraAccountManager")
                .getMethod("getXiaomiAccount", Context.class);
    }

    private static Application passwordsApp(ClassLoader loader) throws ReflectiveOperationException {
        Field instance = loader.loadClass(PASSWORDS + ".PasswordsApp").getDeclaredField("g");
        instance.setAccessible(true);
        return (Application) instance.get(null);
    }

    private void logFailure(String operation, Throwable failure) {
        Throwable cause = failure instanceof InvocationTargetException ? failure.getCause() : failure;
        log(Log.WARN, TAG, operation + " failed: " + cause.getClass().getSimpleName());
    }

    private boolean matchesApk(String sourceDir, String expected) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        try (InputStream apk = Files.newInputStream(Path.of(sourceDir))) {
            byte[] buffer = new byte[64 * 1024];
            for (int size; (size = apk.read(buffer)) != -1;) {
                sha.update(buffer, 0, size);
            }
        }
        return expected.equals(HexFormat.of().formatHex(sha.digest()));
    }
}
