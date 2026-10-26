package com.cipherveil.protector;

import android.animation.ObjectAnimator;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AnimationUtils;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.cipherveil.protector.ui.FeatureAdapter;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private TextView txtFileName, txtStatus, txtConsole;
    private ProgressBar progressBar;
    private Button btnSelect, btnStart;
    private FeatureAdapter featureAdapter;

    private Uri selectedUri;
    private String selectedName = null;
    private long selectedSize = 0L;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private final ActivityResultLauncher<String[]> pickApkLauncher =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
                if (uri == null) return;
                selectedUri = uri;
                resolveFileMeta(uri);
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        txtFileName = findViewById(R.id.txt_file_name);
        txtStatus = findViewById(R.id.txt_status);
        txtConsole = findViewById(R.id.txt_console);
        progressBar = findViewById(R.id.progress_bar);
        btnSelect = findViewById(R.id.btn_select_apk);
        btnStart = findViewById(R.id.btn_start);

        findViewById(R.id.icon_shield).startAnimation(AnimationUtils.loadAnimation(this, R.anim.pulse));

        RecyclerView recycler = findViewById(R.id.recycler_features);
        recycler.setLayoutManager(new LinearLayoutManager(this));
        featureAdapter = new FeatureAdapter(this, getResources().getStringArray(R.array.feature_list));
        recycler.setAdapter(featureAdapter);

        btnSelect.setOnClickListener(v -> pickApkLauncher.launch(new String[]{"application/vnd.android.package-archive"}));
        btnStart.setOnClickListener(v -> startProtection());
    }

    private void resolveFileMeta(Uri uri) {
        String name = "unknown.apk";
        long size = 0L;
        try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                int sizeIdx = c.getColumnIndex(OpenableColumns.SIZE);
                if (nameIdx >= 0) name = c.getString(nameIdx);
                if (sizeIdx >= 0) size = c.getLong(sizeIdx);
            }
        } catch (Exception ignored) {
        }

        selectedName = name;
        selectedSize = size;

        String sizeLabel = size > 0 ? (size / (1024 * 1024)) + " MB" : "unknown size";
        txtFileName.setText(name + "  //  " + sizeLabel);

        if (size > ProtectionEngine.MAX_APK_BYTES) {
            txtFileName.append("\n[!] EXCEEDS 1GB LIMIT");
        }
    }

    private void startProtection() {
        if (selectedUri == null) {
            Toast.makeText(this, "আগে একটা APK সিলেক্ট করো", Toast.LENGTH_SHORT).show();
            return;
        }

        btnStart.setEnabled(false);
        btnSelect.setEnabled(false);
        txtConsole.setText("[CipherVeil] job started_\n");
        progressBar.setProgress(0);
        setStatus("INITIALIZING...");

        String[] names = getResources().getStringArray(R.array.feature_list);
        boolean[] selected = featureAdapter.getSelections();

        ProtectionEngine engine = new ProtectionEngine(this);

        executor.execute(() -> engine.run(selectedUri, selectedName, selectedSize, names, selected,
                new ProtectionEngine.ProgressListener() {
                    @Override
                    public void onProgress(int percent, String logLine) {
                        mainHandler.post(() -> {
                            animateProgressTo(percent);
                            appendLog(logLine);
                            setStatus("PROCESSING // " + percent + "%");
                        });
                    }

                    @Override
                    public void onFinished(File jobManifest, File stagedApk) {
                        mainHandler.post(() -> {
                            setStatus("STAGED — RUN protector.py TO FINALIZE");
                            appendLog("[DONE] manifest: " + jobManifest.getAbsolutePath());
                            appendLog("[DONE] staged apk: " + stagedApk.getAbsolutePath());
                            appendLog("[NEXT] termux: python tools/protector.py --job " + jobManifest.getName());
                            btnStart.setEnabled(true);
                            btnSelect.setEnabled(true);
                        });
                    }

                    @Override
                    public void onError(String message) {
                        mainHandler.post(() -> {
                            setStatus("ERROR");
                            appendLog("[ERR] " + message);
                            btnStart.setEnabled(true);
                            btnSelect.setEnabled(true);
                        });
                    }
                }));
    }

    private void animateProgressTo(int target) {
        ObjectAnimator anim = ObjectAnimator.ofInt(progressBar, "progress", progressBar.getProgress(), target);
        anim.setDuration(260);
        anim.setInterpolator(new AccelerateDecelerateInterpolator());
        anim.start();
    }

    private void appendLog(String line) {
        txtConsole.append(line + "\n");
    }

    private void setStatus(String s) {
        txtStatus.setText(s);
    }
}
