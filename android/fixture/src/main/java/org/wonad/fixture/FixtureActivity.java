package org.wonad.fixture;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.res.Configuration;
import android.graphics.Rect;
import android.hardware.display.DisplayManager;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.Display;
import android.view.InputDevice;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.UUID;
import org.json.JSONException;
import org.json.JSONArray;
import org.json.JSONObject;

/** Native-app observations, independent of the window manager's requested state. */
public abstract class FixtureActivity extends Activity {
    private final String instance = UUID.randomUUID().toString();
    private int keyDowns;
    private int lastKey;
    private int pointerDowns;
    private int mouseDowns;
    private int lastMetaState;
    private int resumeCount;
    private int configurationChanges;
    private String lifecycle = "created";
    private boolean dialogOpen;
    private String dialogInstance;
    private final FixtureKeyJournal keyJournal = new FixtureKeyJournal();
    private boolean topResumed;
    private CompositionEditText input;
    private volatile String observation = "{}";
    private volatile String keyObservation = "{}";

    protected abstract int color();

    @Override public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setBackgroundColor(color());
        content.setPadding(24, 24, 24, 24);
        TextView label = new TextView(this);
        label.setText(getClass().getSimpleName() + "\nClick here and type. Resize or move this window.");
        label.setTextSize(24);
        content.addView(label);
        input = new CompositionEditText(this, this::record);
        input.setSingleLine(true);
        input.setHint("Keyboard / IME test");
        input.setContentDescription("Wonad fixture text input");
        input.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) { }
            @Override public void afterTextChanged(Editable text) { record(); }
        });
        content.addView(input);
        Button dialog = new Button(this);
        dialog.setText("Open dialog");
        dialog.setOnClickListener(v -> {
            AlertDialog window = new AlertDialog.Builder(this)
                    .setTitle("Native Android dialog")
                    .setMessage("This dialog belongs to " + getClass().getSimpleName())
                    .setPositiveButton("Close", null).create();
            final String currentDialog = UUID.randomUUID().toString();
            window.setOnKeyListener((ignored, code, event) -> {
                observeKey("dialog", currentDialog, event);
                return false; // Observe the actual Dialog callback; preserve all stock handling.
            });
            window.setOnDismissListener(ignored -> { dialogOpen = false; dialogInstance = null; record(); });
            dialogInstance = currentDialog;
            window.show();
            dialogOpen = true;
            record();
        });
        content.addView(dialog);
        // Do not automatically open the IME merely by launching the fixture.
        content.setFocusableInTouchMode(true);
        content.requestFocus();
        content.addOnLayoutChangeListener((v, l, t, r, b, ol, ot, or, ob) -> record());
        setContentView(content);
        record();
    }

    @Override public void onResume() {
        super.onResume();
        lifecycle = "resumed";
        resumeCount++;
        record();
    }

    @Override public void onPause() {
        lifecycle = "paused";
        record();
        super.onPause();
    }

    @Override public void onStop() {
        lifecycle = "stopped";
        record();
        super.onStop();
    }

    @Override public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        configurationChanges++;
        record();
    }

    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        record();
    }

    @Override public void onTopResumedActivityChanged(boolean isTopResumedActivity) {
        super.onTopResumedActivityChanged(isTopResumedActivity);
        topResumed = isTopResumedActivity;
        record();
    }

    @Override public boolean dispatchKeyEvent(KeyEvent event) {
        observeKey("base", null, event);
        if (event.getAction() == KeyEvent.ACTION_DOWN) {
            keyDowns++;
            lastKey = event.getKeyCode();
            lastMetaState = event.getMetaState();
            record();
        }
        return super.dispatchKeyEvent(event);
    }

    private void observeKey(String recipient, String currentDialog, KeyEvent event) {
        keyJournal.observe(recipient, currentDialog, event.getAction(), event.getKeyCode(),
                event.getMetaState(), event.getRepeatCount(), event.getDeviceId(), event.getSource(),
                event.getFlags(), event.getDownTime(), event.getEventTime());
        record();
    }

    @Override public boolean dispatchTouchEvent(MotionEvent event) {
        if (event.getAction() == MotionEvent.ACTION_DOWN) {
            pointerDowns++;
            if (event.isFromSource(InputDevice.SOURCE_MOUSE)) mouseDowns++;
            record();
        }
        return super.dispatchTouchEvent(event);
    }

    private void record() {
        Rect bounds = getWindowManager().getCurrentWindowMetrics().getBounds();
        try {
            observation = new JSONObject()
                    .put("component", getComponentName().flattenToShortString())
                    .put("instance", instance).put("task", getTaskId())
                    .put("display", getDisplay().getDisplayId())
                    .put("left", bounds.left).put("top", bounds.top)
                    .put("right", bounds.right).put("bottom", bounds.bottom)
                    .put("focused", hasWindowFocus()).put("key_downs", keyDowns)
                    .put("top_resumed", topResumed)
                    .put("text", input == null ? "" : input.getText().toString())
                    .put("composition", input == null ? null : input.diagnostics())
                    .put("last_key", lastKey).put("pointer_downs", pointerDowns)
                    .put("mouse_downs", mouseDowns).put("last_meta_state", lastMetaState)
                    .put("lifecycle", lifecycle).put("resume_count", resumeCount)
                    .put("configuration_changes", configurationChanges)
                    .put("dialog_open", dialogOpen)
                    .put("run", getIntent().getStringExtra("wonad_run"))
                    .toString();
            FixtureKeyJournal.Snapshot keys = keyJournal.snapshot();
            JSONArray entries = new JSONArray();
            for (FixtureKeyJournal.Entry entry : keys.getEntries()) {
                entries.put(new JSONObject().put("sequence", entry.getSequence())
                        .put("recipient", entry.getRecipient())
                        .put("dialog_instance", entry.getDialogInstance() == null ? JSONObject.NULL : entry.getDialogInstance())
                        .put("action", entry.getAction()).put("key", entry.getKey())
                        .put("meta", entry.getMeta()).put("repeat", entry.getRepeat())
                        .put("device", entry.getDevice()).put("source", entry.getSource())
                        .put("flags", entry.getFlags()).put("down_time", entry.getDownTime())
                        .put("event_time", entry.getEventTime()));
            }
            keyObservation = new JSONObject().put("schema", 1)
                    .put("component", getComponentName().flattenToShortString())
                    .put("instance", instance).put("task", getTaskId())
                    .put("display", getDisplay().getDisplayId())
                    .put("dialog_instance", dialogInstance == null ? JSONObject.NULL : dialogInstance)
                    .put("capacity", FixtureKeyJournal.CAPACITY).put("total", keys.getTotal())
                    .put("entries", entries).toString();
        } catch (JSONException impossible) {
            throw new AssertionError(impossible);
        }
    }

    @Override public void dump(String prefix, FileDescriptor fd, PrintWriter writer,
                               String[] args) {
        super.dump(prefix, fd, writer, args);
        writer.println(prefix + "WONAD_OBSERVATION " + observation);
        writer.println(prefix + "WONAD_KEY_JOURNAL " + keyObservation);
        JSONArray displays = new JSONArray();
        for (Display display : getSystemService(DisplayManager.class).getDisplays()) {
            displays.put(display.getDisplayId());
        }
        writer.println(prefix + "WONAD_DISPLAYS " + displays);
    }
}
