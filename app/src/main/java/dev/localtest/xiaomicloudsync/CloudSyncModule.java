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

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

public final class CloudSyncModule extends XposedModule {
    private static final String TAG = "XiaomiCloudSyncTest";
    private static final String PASSWORDS = "com.miui.passwords";
    private static final String CLOUD = PasskeyBridge.CLOUD;
    private static final String FIDO_ASM = "com.fido.asm";
    private static final String FIDO_CALLBACK = "com.miui.credential.ICredentialPassService";

    private final AtomicBoolean gateLogged = new AtomicBoolean();
    private final AtomicBoolean syncRequested = new AtomicBoolean();
    // Accessed only by the debounced callback on the process main looper.
    private Account periodicAccount;
    private record ScheduledSync(Account account, SyncResult result) {}

    private final ThreadLocal<ScheduledSync> stockSync = new ThreadLocal<>();
    private final ThreadLocal<Account> legacyAccount = new ThreadLocal<>();

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!param.isFirstPackage() || !"marble".equals(Build.DEVICE)) {
            return;
        }

        String process = Application.getProcessName();
        String name = param.getPackageName();
        ClassLoader loader = param.getClassLoader();
        try (HookGroup hooks = new HookGroup()) {
            if (CLOUD.equals(name) && CLOUD.equals(process)) {
                registerCloudGate(loader, hooks);
                registerVersionReader(loader, hooks);
            } else if (PASSWORDS.equals(name) && (PASSWORDS + ":sync").equals(process)) {
                Method account = xiaomiAccount(loader);
                Field app = passwordsAppField(loader);
                registerPasskeySync(loader, hooks, account, app);
                registerNativeEvents(loader, hooks, account, app);
            } else if (PASSWORDS.equals(name) && PASSWORDS.equals(process)) {
                registerScheduling(loader, hooks);
            } else {
                return;
            }
            hooks.activate();
            log(Log.INFO, TAG, "Passkey sync hooks active in " + process);
        } catch (ReflectiveOperationException failure) {
            log(Log.WARN, TAG, "Incompatible hook targets in " + process + ": " + failure);
        } catch (RuntimeException | LinkageError failure) {
            logFailure("Hook setup in " + process, failure);
        }
    }

    private void registerCloudGate(ClassLoader loader, HookGroup hooks) throws ReflectiveOperationException {
        Class<?> appKeys = loader.loadClass("B2.a");
        Method supportsFido = requiredMethod(appKeys, "e", boolean.class);
        deoptimize(appKeys.getDeclaredMethod("f", Context.class));
        Class<?> passwordSync = loader.loadClass("y2.a");
        deoptimize(passwordSync.getDeclaredMethod("g", Context.class, String.class));
        hooks.intercept(supportsFido, chain -> {
            if (gateLogged.compareAndSet(false, true)) {
                log(Log.INFO, TAG, "Skipped modern FIDO initialization in CloudService");
            }
            return false;
        });
    }

    private void registerVersionReader(ClassLoader loader, HookGroup hooks) throws ReflectiveOperationException {
        Class<?> stub = loader.loadClass(PasskeyBridge.KEYBOX_DESCRIPTOR + "$Stub");
        Method onTransact = requiredMethod(stub, "onTransact", boolean.class,
                int.class, Parcel.class, Parcel.class, int.class);
        Method cloudApp = requiredStatic(loader.loadClass(CLOUD + ".CloudApp").getDeclaredMethod("g"),
                Context.class);
        Method account = xiaomiAccount(loader);
        Class<?> keyBag = loader.loadClass("vendor.xiaomi.hardware.mikeybag.IMiKeyBagService");
        Method nativeService = requiredStatic(loader.loadClass("R1.g").getDeclaredMethod("e"), keyBag);
        Method nativeVersion = keyBag.getMethod("getMasterKeyVersion", String.class);
        if (nativeVersion.getReturnType() != long.class || Modifier.isStatic(nativeVersion.getModifiers())) {
            throw new NoSuchMethodException(nativeVersion.toString());
        }
        hooks.intercept(onTransact, chain -> {
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
    }

    private void registerPasskeySync(ClassLoader loader, HookGroup hooks, Method accountLookup, Field app)
            throws ReflectiveOperationException {
        PasskeyBridge.Targets targets = PasskeyBridge.resolveTargets(loader, accountLookup);
        Method onPerformSync = requiredMethod(loader.loadClass("T3.e"), "onPerformSync", void.class,
                Account.class, Bundle.class, String.class, ContentProviderClient.class, SyncResult.class);
        hooks.intercept(onPerformSync, chain -> {
            stockSync.set(new ScheduledSync((Account) chain.getArg(0), (SyncResult) chain.getArg(4)));
            try {
                return chain.proceed();
            } finally {
                stockSync.remove();
            }
        });
        Class<?> fidoSync = loader.loadClass("O2.e");
        hooks.intercept(accountLookup, chain -> {
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
        Method cloudEnvironment = requiredStatic(loader.loadClass("R3.c").getDeclaredMethod("b"),
                requestEnvironment);
        Field environmentBuilder = requestEnvironment.getDeclaredField("b");
        Field tokenProvider = loader.loadClass("X3.a").getDeclaredField("b");
        Field cache = loader.loadClass("M4.h").getDeclaredField("b");
        if (environmentBuilder.getType().isPrimitive() || tokenProvider.getType().isPrimitive()
                || !ThreadLocal.class.isAssignableFrom(cache.getType())) {
            throw new NoSuchFieldException("Unexpected cloud request environment fields");
        }
        deoptimize(loader.loadClass("P2.d").getDeclaredMethod("d", Bundle.class));
        deoptimize(requestEnvironment.getDeclaredMethod("t"));
        hooks.intercept(requiredMethod(fidoSync, "c", void.class), chain -> {
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
                        PasskeyBridge bridge = new PasskeyBridge((Application) app.get(null), targets);
                        report = bridge.sync(run.account);
                    } finally {
                        legacyAccount.remove();
                        requestToken.remove();
                        if (stockToken != null) {
                            requestToken.set(stockToken);
                        }
                    }
                    if (report != null) {
                        log(Log.INFO, TAG, "Legacy passkey sync uploaded=" + report.uploaded
                                + " restored=" + report.restored + " deleted=" + report.deleted
                                + " pending=" + report.pending + " received=" + report.received
                                + " conflicts=" + report.conflicts + " retry=" + report.retry);
                        frameworkResult.moreRecordsToGet |= report.morePages;
                        if (report.retry) {
                            frameworkResult.stats.numIoExceptions++;
                        }
                    }
                } catch (InterruptedException cancelled) {
                    Thread.currentThread().interrupt();
                } catch (Exception | LinkageError failure) {
                    frameworkResult.stats.numIoExceptions++;
                    logFailure("Legacy passkey sync", failure);
                }
            }
            return null;
        });
        // The phone's KeyBag ABI cannot service the modern FIDO sync path.
        // These three methods belong to FIDO only; the Passwords adapter remains native.
        hooks.intercept(requiredMethod(fidoSync, "b", void.class), chain -> null);
        hooks.intercept(requiredMethod(fidoSync, "e", void.class), chain -> null);
    }

    private void registerNativeEvents(ClassLoader loader, HookGroup hooks, Method accountLookup, Field appField)
            throws ReflectiveOperationException {
        Method onTransact = requiredMethod(loader.loadClass("O2.a"), "onTransact", boolean.class,
                int.class, Parcel.class, Parcel.class, int.class);
        hooks.intercept(onTransact, chain -> {
            if ((Integer) chain.getArg(0) != 1 || !(chain.getThisObject() instanceof Binder instance)
                    || !FIDO_CALLBACK.equals(instance.getInterfaceDescriptor())) {
                return chain.proceed();
            }
            Application app;
            try {
                app = (Application) appField.get(null);
                if (!callerIs(app, Binder.getCallingUid(), FIDO_ASM)) {
                    return chain.proceed();
                }
                noteNativeRemoval(app, accountLookup, (Parcel) chain.getArg(1));
            } catch (Exception failure) {
                logFailure("Native passkey event", failure);
                return chain.proceed();
            }
            Object result = chain.proceed();
            if (Boolean.TRUE.equals(result)) {
                requestSoon(app, accountLookup);
            }
            return result;
        });
    }

    private static void noteNativeRemoval(Application app, Method accountLookup, Parcel original) throws Exception {
        Parcel payload = Parcel.obtain();
        try {
            payload.appendFrom(original, 0, original.dataSize());
            payload.setDataPosition(original.dataPosition());
            payload.enforceInterface(FIDO_CALLBACK);
            if (payload.readByte() != 3) {
                return;
            }
            ArrayList<String> credentials = payload.createStringArrayList();
            Account account = (Account) accountLookup.invoke(null, app);
            if (account != null && credentials != null && !credentials.isEmpty()) {
                PasskeyBridge.noteNativeRemoval(app, account, credentials);
            }
        } finally {
            payload.recycle();
        }
    }

    private void registerScheduling(ClassLoader loader, HookGroup hooks) throws ReflectiveOperationException {
        Field instance = passwordsAppField(loader);
        Method accountLookup = xiaomiAccount(loader);
        hooks.intercept(requiredMethod(instance.getDeclaringClass(), "onCreate", void.class), chain -> {
            Object result = chain.proceed();
            requestSoon((Application) chain.getThisObject(), accountLookup);
            return result;
        });
        Class<?> provider = loader.loadClass(PASSWORDS + ".datacenter.db.PrivacyDataProvider");
        Method update = requiredMethod(provider, "update", int.class, Uri.class, ContentValues.class,
                String.class, String[].class);
        hooks.intercept(update, chain -> {
            Object result = chain.proceed();
            Uri uri = (Uri) chain.getArg(0);
            ContentValues values = (ContentValues) chain.getArg(1);
            if (result instanceof Integer count && count > 0 && uri != null && values != null
                    && "content://miui.autofill/fido_credential_summary_record".equals(uri.toString())
                    && values.containsKey("localStatus")) {
                try {
                    requestSoon((Application) instance.get(null), accountLookup);
                } catch (Exception failure) {
                    logFailure("Passkey management change", failure);
                }
            }
            return result;
        });
    }

    private void requestSoon(Application app, Method accountLookup) {
        if (app == null || !syncRequested.compareAndSet(false, true)) {
            return;
        }
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            syncRequested.set(false);
            try {
                Account current = (Account) accountLookup.invoke(null, app);
                if (current != null && ContentResolver.getMasterSyncAutomatically()
                        && ContentResolver.getSyncAutomatically(current, PasskeyBridge.AUTHORITY)) {
                    Bundle extras = PasskeyBridge.syncExtras();
                    ContentResolver.requestSync(current, PasskeyBridge.AUTHORITY, extras);
                    if (!current.equals(periodicAccount)) {
                        ContentResolver.addPeriodicSync(current, PasskeyBridge.AUTHORITY, extras, 15 * 60L);
                        periodicAccount = current;
                    }
                } else {
                    periodicAccount = null;
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
        return requiredStatic(loader.loadClass("miui.accounts.ExtraAccountManager")
                .getMethod("getXiaomiAccount", Context.class), Account.class);
    }

    private static Field passwordsAppField(ClassLoader loader) throws ReflectiveOperationException {
        Field instance = loader.loadClass(PASSWORDS + ".PasswordsApp").getDeclaredField("g");
        if (!Modifier.isStatic(instance.getModifiers()) || !Application.class.isAssignableFrom(instance.getType())) {
            throw new NoSuchFieldException(instance.toString());
        }
        instance.setAccessible(true);
        return instance;
    }

    private static Method requiredMethod(Class<?> type, String name, Class<?> returnType, Class<?>... parameters)
            throws NoSuchMethodException {
        Method method = type.getDeclaredMethod(name, parameters);
        if (method.getReturnType() != returnType) {
            throw new NoSuchMethodException(method.toString());
        }
        return method;
    }

    private static Method requiredStatic(Method method, Class<?> returnType) throws NoSuchMethodException {
        if (!Modifier.isStatic(method.getModifiers()) || !returnType.isAssignableFrom(method.getReturnType())) {
            throw new NoSuchMethodException(method.toString());
        }
        return method;
    }

    private void logFailure(String operation, Throwable failure) {
        Throwable cause = failure instanceof InvocationTargetException ? failure.getCause() : failure;
        log(Log.WARN, TAG, operation + " failed: " + cause.getClass().getSimpleName());
    }

    private final class HookGroup implements AutoCloseable {
        private final ArrayList<HookHandle> handles = new ArrayList<>();
        private volatile boolean active;

        void intercept(Method method, Hooker hooker) {
            handles.add(hook(method).intercept(chain -> active ? hooker.intercept(chain) : chain.proceed()));
        }

        void activate() {
            active = true;
            handles.clear();
        }

        @Override
        public void close() {
            for (int index = handles.size() - 1; index >= 0; index--) {
                try {
                    handles.get(index).unhook();
                } catch (RuntimeException | LinkageError failure) {
                    logFailure("Removing inactive hook", failure);
                }
            }
        }
    }
}
