package com.purdue.kpoc.verify;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Intent entry point for app-context verification.
 *
 * Extras:
 *   lib_path  app-local shared object path
 *   apk_path  installed helper APK path (for JNI mode)
 *   mode      "preload" or "jni"
 *   port      loopback TCP port to serve child stdio on
 *   pump      whether to serve child stdio over the socket
 *
 * The child command is the same one regular shared mode uses:
 *   LD_PRELOAD=<lib> /system/bin/sleep 200
 */
public final class RunActivity extends Activity {
    private static final String TAG = "KPOC_VERIFY";
    private volatile Process process;
    private volatile ServerSocket server;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        final String libPath = getIntent().getStringExtra("lib_path");
        final String apkPath = getIntent().getStringExtra("apk_path");
        final String mode = getIntent().getStringExtra("mode");
        final int port = getIntent().getIntExtra("port", 0);
        final boolean pump = getIntent().getBooleanExtra("pump", true);

        Thread worker = new Thread(() -> runPayload(libPath, apkPath, mode, port, pump));
        worker.setDaemon(true);
        worker.start();
    }

    private void runPayload(
            String libPath,
            String apkPath,
            String mode,
            int port,
            boolean pump) {
        Socket client = null;
        try {
            String command;
            if ("jni".equals(mode)) {
                command = "CLASSPATH=" + shellQuote(apkPath)
                        + " /system/bin/app_process /system/bin "
                        + "com.purdue.kpoc.verify.Loader " + shellQuote(libPath);
            } else {
                command = "LD_PRELOAD=" + shellQuote(libPath)
                        + " /system/bin/sleep 200";
            }
            Log.i(TAG, "starting app child: " + command);
            process = new ProcessBuilder("/system/bin/sh", "-c", command).start();

            if (pump) {
                server = new ServerSocket(port, 1, InetAddress.getByName("127.0.0.1"));
                Log.i(TAG, "waiting for verifier on 127.0.0.1:" + port);
                client = server.accept();
                Log.i(TAG, "verifier connected");
                Thread stdoutPump = pump(process.getInputStream(), client.getOutputStream());
                Thread stderrPump = pump(process.getErrorStream(), client.getOutputStream());
                Thread stdinPump = pump(client.getInputStream(), process.getOutputStream());
                process.waitFor();
                // Let stdout/stderr drain into the still-open socket before
                // closing it; closing first can discard the final shell output.
                joinQuietly(stdoutPump);
                joinQuietly(stderrPump);
                closeQuietly(client);
                joinQuietly(stdinPump);
            } else {
                Thread stdoutLog = logStream(process.getInputStream(), Log.INFO);
                Thread stderrLog = logStream(process.getErrorStream(), Log.ERROR);
                int exitCode = process.waitFor();
                Log.i(TAG, "app child exited: " + exitCode);
                joinQuietly(stdoutLog);
                joinQuietly(stderrLog);
            }
        } catch (Exception exc) {
            Log.e(TAG, "app child failed", exc);
        } finally {
            closeQuietly(process);
            closeQuietly(client);
            closeQuietly(server);
            runOnUiThread(this::finish);
        }
    }

    private static Thread logStream(InputStream input, int priority) {
        Thread thread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(input))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    Log.println(priority, TAG, "child: " + line);
                }
            } catch (IOException ignored) {
                // Process teardown race.
            }
        });
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static Thread pump(InputStream input, OutputStream output) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[16384];
            try {
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    output.write(buffer, 0, read);
                    output.flush();
                }
            } catch (IOException ignored) {
                // Process/socket teardown races are normal here.
            }
        });
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static String shellQuote(String value) {
        if (value == null) {
            return "''";
        }
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static void joinQuietly(Thread thread) {
        try {
            thread.join(5000L);
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
        }
    }

    private static void closeQuietly(AutoCloseable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (Exception ignored) {
            // Best-effort cleanup.
        }
    }

    private static void closeQuietly(Process value) {
        if (value != null) {
            value.destroy();
        }
    }
}
