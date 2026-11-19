package dev.localtest.xiaomicloudsync;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.DeadObjectException;
import android.os.IBinder;
import android.os.RemoteException;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

final class BoundService implements AutoCloseable, ServiceConnection {
    private final Context context;
    private final CompletableFuture<IBinder> connected = new CompletableFuture<>();

    BoundService(Context context, String action, String packageName) throws RemoteException {
        this.context = context;
        if (!context.bindService(new Intent(action).setPackage(packageName), this,
                Context.BIND_AUTO_CREATE)) {
            throw new RemoteException("Unable to bind native service");
        }
    }

    IBinder binder() throws Exception {
        try {
            return connected.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException failure) {
            if (failure.getCause() instanceof RemoteException remote) {
                throw remote;
            }
            throw failure;
        }
    }

    @Override
    public void onServiceConnected(ComponentName component, IBinder binder) {
        connected.complete(binder);
    }

    @Override
    public void onServiceDisconnected(ComponentName component) {
        connected.obtrudeException(new DeadObjectException());
    }

    @Override
    public void onBindingDied(ComponentName component) {
        connected.obtrudeException(new DeadObjectException());
    }

    @Override
    public void onNullBinding(ComponentName component) {
        connected.completeExceptionally(new RemoteException("Native service rejected binding"));
    }

    @Override
    public void close() {
        context.unbindService(this);
    }
}
