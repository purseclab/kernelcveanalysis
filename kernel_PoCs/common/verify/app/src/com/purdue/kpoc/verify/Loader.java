package com.purdue.kpoc.verify;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

public final class Loader {
    private static final long CHILD_WAIT_SECONDS = 180L;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: Loader <library>");
            System.exit(2);
        }
        System.load(args[0]);
        System.out.println("KPOC_APP_LOADED " + args[0]);

        // JNI_OnLoad forks the exploit process. Keep this app_process alive
        // while that child has the ADB stdin/stdout pipe open. Shared-object
        // constructors normally exec a shell and replace us before this point.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(CHILD_WAIT_SECONDS);
        while (System.nanoTime() < deadline && hasChildren()) {
            Thread.sleep(50L);
        }
    }

    private static boolean hasChildren() {
        File[] tasks = new File("/proc/self/task").listFiles();
        if (tasks == null) {
            return false;
        }
        for (File task : tasks) {
            File children = new File(task, "children");
            if (!children.isFile()) {
                continue;
            }
            try (BufferedReader reader = new BufferedReader(new FileReader(children))) {
                String line = reader.readLine();
                if (line != null && !line.trim().isEmpty()) {
                    return true;
                }
            } catch (IOException ignored) {
                // /proc can race with task exit; treat an unreadable file as empty.
            }
        }
        return false;
    }
}
