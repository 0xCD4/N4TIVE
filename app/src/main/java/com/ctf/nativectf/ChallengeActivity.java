package com.ctf.nativectf;

import android.app.Activity;
import android.content.Context;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.ctf.nativectf.challenges.Ch01;
import com.ctf.nativectf.challenges.Ch02;
import com.ctf.nativectf.challenges.Ch03;
import com.ctf.nativectf.challenges.Ch04;
import com.ctf.nativectf.challenges.Ch05;
import com.ctf.nativectf.challenges.Ch06;
import com.ctf.nativectf.challenges.Ch07;
import com.ctf.nativectf.challenges.Ch08;

/** One challenge: what it is about, how to reach it, and where to hand in the flag. */
public class ChallengeActivity extends Activity {

    static final String EXTRA_INDEX = "challenge_index";

    private static final String[] CHECK_NAMES = {
        "TracerPid", "Frida in memory maps", "ptrace self-attach", "Timing",
        "Breakpoint scan", "Java debugger", "APK signature"
    };

    private Ui ui;
    private int index;
    private Challenges.Item item;
    private EditText flagInput;
    private TextView status;
    private LinearLayout result;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ui = new Ui(this);
        ui.systemBars();

        index = getIntent().getIntExtra(EXTRA_INDEX, 0);
        if (index < 0 || index >= Challenges.ALL.length) index = 0;
        item = Challenges.ALL[index];

        LinearLayout page = ui.column();
        page.setPadding(ui.dp(24), ui.dp(20), ui.dp(24), ui.dp(44));

        TextView back = ui.label("‹  All challenges", ui.sans(500), 15, ui.accent);
        back.setPadding(0, ui.dp(12), ui.dp(16), ui.dp(12));
        back.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) { finish(); }
        });
        page.addView(back, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView meta = ui.label("Challenge " + item.number() + ", level " + item.level
                + " of " + Challenges.MAX_LEVEL, ui.sans(500), 13, ui.mute);
        page.addView(meta, ui.below(18));

        TextView title = ui.label(item.title, ui.serif(520, 48), 34, ui.ink);
        title.setLetterSpacing(-0.014f);
        title.setLineSpacing(0, 0.92f);
        page.addView(title, ui.below(10));

        page.addView(ui.label(item.library, ui.sans(400), 14, ui.mute), ui.below(10));
        page.addView(ui.rule(ui.ink), ruleBelow(24));

        TextView summary = ui.label(item.summary, ui.sans(400), 16.5f, ui.ink);
        summary.setLineSpacing(0, 1.2f);
        page.addView(summary, ui.below(24));

        section(page, "Interface", item.contact);
        section(page, "Approach", item.approach);

        page.addView(ui.rule(ui.line), ruleBelow(30));
        page.addView(heading("Flag"), ui.below(26));

        flagInput = flagField();
        page.addView(flagInput, ui.below(10));

        TextView submit = ui.primaryButton("Submit flag");
        submit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) { submitFlag(); }
        });
        page.addView(submit, ui.below(12));

        status = ui.label("", ui.sans(500), 15, ui.mute);
        page.addView(status, ui.below(16));
        showSolved(Progress.isSolved(this, item.id));

        addAction(page);

        result = ui.column();
        result.setBackground(ui.box(ui.sunken, ui.line));
        result.setPadding(ui.dp(16), ui.dp(14), ui.dp(16), ui.dp(14));
        result.setVisibility(View.GONE);
        page.addView(result, ui.below(12));

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(ui.paper);
        scroll.setFillViewport(true);
        scroll.addView(page);
        setContentView(scroll);
    }

    private TextView heading(String text) {
        return ui.label(text, ui.sans(600), 13, ui.mute);
    }

    private void section(LinearLayout page, String name, String body) {
        page.addView(heading(name), ui.below(24));
        TextView text = ui.label(body, ui.sans(400), 15.5f, ui.ink);
        text.setLineSpacing(0, 1.2f);
        page.addView(text, ui.below(7));
    }

    private EditText flagField() {
        EditText field = new EditText(this);
        field.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        field.setSingleLine(true);
        field.setTypeface(Typeface.MONOSPACE);
        field.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        field.setTextColor(ui.ink);
        field.setHint("FLAG{...}");
        field.setHintTextColor((ui.mute & 0x00FFFFFF) | 0x99000000);
        field.setBackground(ui.box(ui.sunken, ui.line));
        field.setPadding(ui.dp(14), ui.dp(15), ui.dp(14), ui.dp(15));
        field.setImeOptions(EditorInfo.IME_ACTION_DONE);
        field.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView view, int action, KeyEvent event) {
                if (action == EditorInfo.IME_ACTION_DONE) {
                    submitFlag();
                    return true;
                }
                return false;
            }
        });
        return field;
    }

    private void showSolved(boolean solved) {
        status.setText(solved ? "Solved" : "Unsolved");
        status.setTextColor(solved ? ui.ink : ui.mute);
        status.setTypeface(ui.sans(solved ? 600 : 500));
    }

    private void submitFlag() {
        String input = flagInput.getText().toString().trim();
        if (input.isEmpty()) {
            status.setText("Enter a flag first.");
            status.setTextColor(ui.mute);
            status.setTypeface(ui.sans(500));
            return;
        }

        boolean correct;
        try {
            correct = verify(input);
        } catch (Throwable error) {
            status.setText("The library could not be called. " + error.getClass().getSimpleName());
            status.setTextColor(ui.accent);
            return;
        }

        if (correct) {
            Progress.markSolved(this, item.id);
            showSolved(true);
            InputMethodManager keyboard = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            if (keyboard != null) keyboard.hideSoftInputFromWindow(flagInput.getWindowToken(), 0);
        } else {
            status.setText("That is not the flag.");
            status.setTextColor(ui.accent);
            status.setTypeface(ui.sans(500));
        }
    }

    private boolean verify(String input) {
        switch (index) {
            case 0: return new Ch01().verifyFlag(input);
            case 1: return new Ch02().verifyFlag(input);
            case 2: return new Ch03().verifyFlag(input);
            case 3: return new Ch04().verifyFlag(input);
            case 4: return new Ch05().verifyFlag(input);
            case 5: return new Ch06().verifyFlag(input);
            case 6: return new Ch07().verifyFlag(input);
            case 7: return new Ch08().verifyFlag(input);
            default: return false;
        }
    }

    /** Two challenges offer something to run from the screen itself. */
    private void addAction(LinearLayout page) {
        String text;
        if (index == 0) text = "Run solve()";
        else if (index == 3) text = "Run the seven checks";
        else return;

        page.addView(ui.rule(ui.line), ruleBelow(30));
        page.addView(heading("Try it"), ui.below(26));
        TextView action = ui.secondaryButton(text);
        action.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    if (index == 0) showHint(new Ch01().solve());
                    else showChecks(new Ch04().checkStatus(ChallengeActivity.this));
                } catch (Throwable error) {
                    showHint("The library could not be called. " + error.getClass().getSimpleName());
                }
            }
        });
        page.addView(action, ui.below(10));
    }

    private void showHint(String text) {
        result.removeAllViews();
        TextView line = ui.label(text, Typeface.MONOSPACE, 14, ui.ink);
        line.setLineSpacing(0, 1.15f);
        result.addView(line);
        result.setVisibility(View.VISIBLE);
    }

    /** One row per check, in the order the library runs them. */
    private void showChecks(int bits) {
        result.removeAllViews();
        for (int i = 0; i < CHECK_NAMES.length; i++) {
            boolean passed = ((bits >> i) & 1) == 1;
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setPadding(0, ui.dp(6), 0, ui.dp(6));
            row.addView(ui.label(CHECK_NAMES[i], ui.sans(400), 15, ui.ink),
                    new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            TextView verdict = ui.label(passed ? "pass" : "fail",
                    ui.sans(passed ? 500 : 600), 15, passed ? ui.mute : ui.accent);
            verdict.setGravity(Gravity.END);
            row.addView(verdict);
            result.addView(row);
        }
        result.setVisibility(View.VISIBLE);
    }

    private LinearLayout.LayoutParams ruleBelow(int topDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, ui.dp(1)));
        params.topMargin = ui.dp(topDp);
        return params;
    }
}
