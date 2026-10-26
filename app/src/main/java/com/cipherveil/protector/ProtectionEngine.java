package com.cipherveil.protector;

import android.content.Context;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * On-device half of CipherVeil's pipeline.
 *
 * Decompiling/re-assembling DEX, encrypting resources and re-signing an
 * APK is heavy, long-running work that does not belong on a UI thread or
 * inside a memory-constrained phone process for files up to 1 GB. So this
 * class is deliberately scoped to what a phone CAN do reliably and fast:
 *
 *   1. Stream-copy the selected APK into app storage in fixed-size chunks
 *      (never holds the whole file in RAM, regardless of its size).
 *   2. Feed each chunk to the native FNV-1a hasher to build a tamper-evident
 *      fingerprint of the original file.
 *   3. Write a job manifest (protection_job.json) describing exactly which
 *      of the 20+ matrix features were selected.
 *
 * The heavy lifting (obfuscation, encryption, DEX repacking, zipalign,
 * re-signing) is done by tools/protector.py, which this same job manifest
 * drives — run it locally in Termux (fits the phone-only workflow this
 * app's user already has) or as a GitHub Actions / CI step.
 */
public class ProtectionEngine {

    private static final int CHUNK_SIZE = 1024 * 1024; // 1 MB streaming chunks
    public static final long MAX_APK_BYTES = 1024L * 1024L * 1024L; // 1 GB

    public interface ProgressListener {
        void onProgress(int percent, String logLine);
        void onFinished(File jobManifest, File stagedApk);
        void onError(String message);
    }

    private final Context context;

    public ProtectionEngine(Context context) {
        this.context = context.getApplicationContext();
    }

    public void run(Uri apkUri, String displayName, long sizeBytes,
                     String[] featureNames, boolean[] selected,
                     ProgressListener listener) {
        try {
            if (sizeBytes > MAX_APK_BYTES) {
                listener.onError("FILE EXCEEDS 1GB LIMIT (" + (sizeBytes / (1024 * 1024)) + " MB)");
                return;
            }

            File workDir = new File(context.getFilesDir(), "cipherveil_jobs");
            if (!workDir.exists()) workDir.mkdirs();

            File staged = new File(workDir, "staged_" + System.currentTimeMillis() + ".apk");
            listener.onProgress(5, "[*] staging target -> " + staged.getName());

            String fingerprint = streamCopyAndFingerprint(apkUri, staged, sizeBytes, listener);
            listener.onProgress(70, "[*] native fingerprint: " + fingerprint);

            JSONObject job = buildJobManifest(displayName, staged, sizeBytes, fingerprint, featureNames, selected);
            File manifestFile = new File(workDir, "protection_job.json");
            try (FileOutputStream fos = new FileOutputStream(manifestFile)) {
                fos.write(job.toString(2).getBytes("UTF-8"));
            }
            listener.onProgress(90, "[*] job manifest written -> " + manifestFile.getName());

            boolean debuggerAttached = NativeGuard.isDebuggerAttached();
            listener.onProgress(96, "[*] runtime self-check // debugger_attached=" + debuggerAttached);

            listener.onProgress(100, "[OK] staged + fingerprinted. hand off to tools/protector.py");
            listener.onFinished(manifestFile, staged);

        } catch (Exception e) {
            listener.onError("ENGINE FAULT: " + e.getMessage());
        }
    }

    private String streamCopyAndFingerprint(Uri src, File dest, long totalBytes,
                                             ProgressListener listener) throws IOException {
        long copied = 0;
        String runningFingerprint = "0000000000000000";

        try (InputStream in = context.getContentResolver().openInputStream(src);
             OutputStream out = new FileOutputStream(dest)) {

            if (in == null) throw new IOException("could not open input stream for selected APK");

            byte[] buffer = new byte[CHUNK_SIZE];
            int read;
            int lastReportedPct = -1;

            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                copied += read;

                byte[] exact = (read == buffer.length) ? buffer : java.util.Arrays.copyOf(buffer, read);
                runningFingerprint = NativeGuard.fingerprint(exact);

                if (totalBytes > 0) {
                    int pct = 5 + (int) ((copied * 60L) / totalBytes); // maps to 5-65%
                    if (pct != lastReportedPct && pct % 5 == 0) {
                        listener.onProgress(Math.min(pct, 65),
                                "[*] streaming... " + (copied / 1024 / 1024) + "MB / " + (totalBytes / 1024 / 1024) + "MB");
                        lastReportedPct = pct;
                    }
                }
            }
        }
        return runningFingerprint;
    }

    private JSONObject buildJobManifest(String displayName, File stagedApk, long sizeBytes,
                                         String fingerprint, String[] names, boolean[] selected) throws JSONException {
        JSONObject job = new JSONObject();
        job.put("app", "CipherVeil");
        job.put("source_name", displayName);
        job.put("staged_path", stagedApk.getAbsolutePath());
        job.put("size_bytes", sizeBytes);
        job.put("native_fingerprint", fingerprint);
        job.put("created_at", System.currentTimeMillis());

        JSONArray features = new JSONArray();
        for (int i = 0; i < names.length; i++) {
            JSONObject f = new JSONObject();
            f.put("name", names[i]);
            f.put("enabled", selected[i]);
            features.put(f);
        }
        job.put("features", features);
        return job;
    }
}
