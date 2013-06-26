/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.IPackageManager;
import android.os.Build;
import android.os.DropBoxManager;
import android.os.FileObserver;
import android.os.FileUtils;
import android.os.RecoverySystem;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.provider.Downloads;
import android.util.Slog;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.Math;

/**
 * Performs a number of miscellaneous, non-system-critical actions
 * after the system has finished booting.
 */
public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "BootReceiver";

    // Maximum size of a logged event (files get truncated if they're longer).
    // Give userdebug builds a larger max to capture extra debug, esp. for last_kmsg.
    private static final int LOG_SIZE =
        SystemProperties.getInt("ro.debuggable", 0) == 1 ? 98304 : 65536;

    private static final File TOMBSTONE_DIR = new File("/data/tombstones");
    private static final File PSTORE_DIR = new File("/data/kpanic/pstore");

    // The pre-froyo package and class of the system updater, which
    // ran in the system process.  We need to remove its packages here
    // in order to clean up after a pre-froyo-to-froyo update.
    private static final String OLD_UPDATER_PACKAGE =
        "com.google.android.systemupdater";
    private static final String OLD_UPDATER_CLASS =
        "com.google.android.systemupdater.SystemUpdateReceiver";

    // Keep a reference to the observer so the finalizer doesn't disable it.
    private static FileObserver sTombstoneObserver = null;

    @Override
    public void onReceive(final Context context, Intent intent) {
        // Log boot events in the background to avoid blocking the main thread with I/O
        new Thread() {
            @Override
            public void run() {
                try {
                    logBootEvents(context);
                } catch (Exception e) {
                    Slog.e(TAG, "Can't log boot events", e);
                }
                try {
                    boolean onlyCore = false;
                    try {
                        onlyCore = IPackageManager.Stub.asInterface(ServiceManager.getService(
                                "package")).isOnlyCoreApps();
                    } catch (RemoteException e) {
                    }
                    if (!onlyCore) {
                        removeOldUpdatePackages(context);
                    }
                } catch (Exception e) {
                    Slog.e(TAG, "Can't remove old update packages", e);
                }

            }
        }.start();
    }

    private void removeOldUpdatePackages(Context context) {
        Downloads.removeAllDownloadsByPackage(context, OLD_UPDATER_PACKAGE, OLD_UPDATER_CLASS);
    }

    private void logBootEvents(Context ctx) throws IOException {
        final DropBoxManager db = (DropBoxManager) ctx.getSystemService(Context.DROPBOX_SERVICE);
        final SharedPreferences prefs = ctx.getSharedPreferences("log_files", Context.MODE_PRIVATE);
        final String headers = new StringBuilder(512)
            .append("Build: ").append(Build.FINGERPRINT).append("\n")
            .append("Hardware: ").append(Build.BOARD).append("\n")
            .append("Revision: ")
            .append(SystemProperties.get("ro.revision", "")).append("\n")
            .append("Bootloader: ").append(Build.BOOTLOADER).append("\n")
            .append("Radio: ").append(Build.RADIO).append("\n")
            .append("Kernel: ")
            .append(FileUtils.readTextFile(new File("/proc/version"), 1024, "...\n"))
            .append("\n").toString();

        String recovery = RecoverySystem.handleAftermath();
        if (recovery != null && db != null) {
            db.addText("SYSTEM_RECOVERY_LOG", headers + recovery);
        }

        if (SystemProperties.getLong("ro.runtime.firstboot", 0) == 0) {
            String now = Long.toString(System.currentTimeMillis());
            SystemProperties.set("ro.runtime.firstboot", now);
            if (db != null) db.addText("SYSTEM_BOOT", headers);

            // Negative sizes mean to take the *tail* of the file (see FileUtils.readTextFile())
            addFileToDropBox(db, prefs, headers, "/proc/last_kmsg",
                    -LOG_SIZE, "SYSTEM_LAST_KMSG");
            addFileToDropBox(db, prefs, headers, "/cache/recovery/log",
                    -LOG_SIZE, "SYSTEM_RECOVERY_LOG");
            addFileToDropBox(db, prefs, headers, "/data/dontpanic/apanic_console",
                    -LOG_SIZE, "APANIC_CONSOLE");
            addFileToDropBox(db, prefs, headers, "/data/dontpanic/apanic_threads",
                    -LOG_SIZE, "APANIC_THREADS");


        } else {
            if (db != null) db.addText("SYSTEM_RESTART", headers);
        }

        /* Handle Linux kernel panics in the pstore.
         *
         * Important things to note:
         * When stored, the oldest messages have the highest number at the end
         * of the filename, and the index begins at 1.
         *
         * Oldest (closest to boot) --> Newest (closest to panic)
         * fileN, fileN-1, fileN-2  --> file2, file1
         *
         * Also, the numbers aren't easily alphabetically sortable because they
         * will appear as:
         * file-1, file-10, file-11, file-2, file-3, ... */

        if (db == null || prefs == null) {
            Slog.e(TAG, "Dropbox or perfs missing; skipping kernel panic dump");
        } else {
            File[] pstoreDirs = null;
            try {
                pstoreDirs = PSTORE_DIR.listFiles();
            } catch (SecurityException e) {
                // Don't kill BootReceiver just because we can't pull the files
                Slog.e(TAG, "Caught security exception", e);
            }
            for (int i = 0; pstoreDirs != null && i < pstoreDirs.length; i++) {
                File thisDir = pstoreDirs[i];
                String dirPath = thisDir.toString();
                String dirName = thisDir.getName();
                String dbFilename = String.format("KPANIC_DMESG.%s", dirName);
                StringBuilder kpanicMsg = new StringBuilder(LOG_SIZE);
                int bytesLost = 0;
                long dirTime = 0;

                if (!pstoreDirs[i].isDirectory())
                    continue;

                // Check whether this panic is already in dropbox.
                dirTime = thisDir.lastModified();
                long lastTime = prefs.getLong(dbFilename, 0);
                if (lastTime == dirTime)
                    continue;

                File[] kpanicFiles = getFilesByPrefix(thisDir, "dmesg-efi-");
                for (int j = 1; kpanicFiles != null && j <= kpanicFiles.length;
                        j++) {
                    File thisFile = new File(dirPath,
                            String.format("dmesg-efi-%d", j));
                    String filePath = thisFile.toString();
                    String fileName = thisFile.getName();

                    if (!thisFile.exists() || !thisFile.canRead()) {
                        String lostFileMsg = String.format(
                                "\n<<Crash Report ERROR loading %s>>\n",
                                filePath);
                        bytesLost += prependToStringBuilder(kpanicMsg,
                                lostFileMsg);
                        Slog.e(TAG, lostFileMsg);
                        continue;
                    }

                    bytesLost += prependToStringBuilder(kpanicMsg,
                            FileUtils.readTextFile(thisFile, 0, null));
                }

                if (bytesLost > 0)
                {
                    String truncMsg = String.format(
                        "<<Crash Report ALERT: lost __1 bytes from %s>>\n",
                        dirName);
                    bytesLost += truncMsg.length() - 3; // 3 for __1
                    int firstBytesLost =
                        String.format("%d", bytesLost).length();
                    bytesLost += firstBytesLost;
                    // Handle the case where we added a digit to the string
                    if (firstBytesLost <
                            String.format("%d", bytesLost).length())
                        bytesLost++;
                    truncMsg.replace("__1", String.format("%d", bytesLost));

                    kpanicMsg.delete(0, truncMsg.length());
                    prependToStringBuilder(kpanicMsg, truncMsg);
                    Slog.i(TAG, truncMsg);
                }

                db.addText(dbFilename, kpanicMsg.toString());
                prefs.edit().putLong(dbFilename, dirTime).apply();

                /* Done handling dmesgs; now handle Android logs.
                 * Android logs are binary, and should be handled as
                 * individual files rather than concatenated. */
                kpanicFiles = getFilesByPrefix(thisDir, "type4-efi-");
                for (int j = 0; kpanicFiles != null && j < kpanicFiles.length;
                        j++)
                {
                    File thisFile = kpanicFiles[j];
                    String fileName = thisFile.getName();
                    /* length() returns long, but shouldn't overflow an int in
                     * this usecase. Unfortunately, the Drop Box APIs don't
                     * currently support a read-buffer-write-repeat model. */
                    byte buffer[] = new byte[(int)thisFile.length()];
                    FileInputStream fileStream;
                    try {
                        fileStream = new FileInputStream(thisFile);
                    } catch (FileNotFoundException e) {
                        Slog.e(TAG, String.format("Could not find alog %s",
                                    fileName));
                        continue;
                    } catch (SecurityException e) {
                        Slog.e(TAG, String.format("Could not open alog %s",
                                    fileName));
                        continue;
                    }
                    if (fileStream.read(buffer) != thisFile.length())
                    {
                        Slog.e(TAG,
                                String.format("Could not read all of alog %s",
                                    fileName));
                        continue;
                    }

                    db.addData(String.format("KPANIC_ALOG.%s.%s", dirName,
                                fileName),
                            buffer, 0);
                }
            }
        }

        // Scan existing tombstones (in case any new ones appeared)
        File[] tombstoneFiles = TOMBSTONE_DIR.listFiles();
        for (int i = 0; tombstoneFiles != null && i < tombstoneFiles.length; i++) {
            addFileToDropBox(db, prefs, headers, tombstoneFiles[i].getPath(),
                    LOG_SIZE, "SYSTEM_TOMBSTONE");
        }

        // Start watching for new tombstone files; will record them as they occur.
        // This gets registered with the singleton file observer thread.
        sTombstoneObserver = new FileObserver(TOMBSTONE_DIR.getPath(), FileObserver.CLOSE_WRITE) {
            @Override
            public void onEvent(int event, String path) {
                try {
                    String filename = new File(TOMBSTONE_DIR, path).getPath();
                    addFileToDropBox(db, prefs, headers, filename, LOG_SIZE, "SYSTEM_TOMBSTONE");
                } catch (IOException e) {
                    Slog.e(TAG, "Can't log tombstone", e);
                }
            }
        };

        sTombstoneObserver.startWatching();
    }

    private static void addFileToDropBox(
            DropBoxManager db, SharedPreferences prefs,
            String headers, String filename, int maxSize, String tag) throws IOException {
        if (db == null || !db.isTagEnabled(tag)) return;  // Logging disabled

        File file = new File(filename);
        long fileTime = file.lastModified();
        if (fileTime <= 0) return;  // File does not exist

        if (prefs != null) {
            long lastTime = prefs.getLong(filename, 0);
            if (lastTime == fileTime) return;  // Already logged this particular file
            // TODO: move all these SharedPreferences Editor commits
            // outside this function to the end of logBootEvents
            prefs.edit().putLong(filename, fileTime).apply();
        }

        Slog.i(TAG, "Copying " + filename + " to DropBox (" + tag + ")");
        db.addText(tag, headers + FileUtils.readTextFile(file, maxSize, "[[TRUNCATED]]\n"));
    }

    private static int prependToStringBuilder(StringBuilder sb, String str)
    {
        int bytesCopied = Math.min(sb.capacity() - sb.length(), str.length());
        int ret = str.length() - bytesCopied;

        sb.insert(0, str.substring(ret, str.length()));

        return ret;
    }

    private static File[] getFilesByPrefix(File directory, final String prefix)
    {
        File[] retFiles = directory.listFiles(
                new FilenameFilter() {
                    public boolean accept(File dir, String name) {
                        return name.startsWith(prefix);
                    }
                });
        return retFiles;
    }

}
