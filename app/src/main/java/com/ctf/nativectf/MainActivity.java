package com.ctf.nativectf;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** The contents page: every challenge with its number, technique and level. */
public class MainActivity extends Activity {

    private Ui ui;
    private final TextView[] solvedMarks = new TextView[Challenges.ALL.length];

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ui = new Ui(this);
        ui.systemBars();

        LinearLayout page = ui.column();
        page.setPadding(ui.dp(24), ui.dp(40), ui.dp(24), ui.dp(44));

        TextView name = ui.label("N4TIVE", ui.serif(560, 60), 42, ui.ink);
        name.setLetterSpacing(-0.014f);
        page.addView(name);

        TextView lead = ui.label(
                "Eight reverse engineering challenges inside the native libraries of an Android app.",
                ui.sans(400), 16.5f, ui.mute);
        lead.setLineSpacing(0, 1.18f);
        page.addView(lead, ui.below(14));

        page.addView(ui.rule(ui.ink), ruleBelow(30));

        for (int i = 0; i < Challenges.ALL.length; i++) {
            page.addView(row(i));
            page.addView(ui.rule(ui.line));
        }

        TextView signature = ui.label("Ahmet Göker, CSINT Research", ui.serif(480, 20), 17, ui.ink);
        page.addView(signature, ui.below(36));
        TextView source = ui.label("github.com/0xCD4/N4TIVE", ui.sans(400), 14, ui.mute);
        page.addView(source, ui.below(6));

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(ui.paper);
        scroll.setFillViewport(true);
        scroll.addView(page);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        for (int i = 0; i < Challenges.ALL.length; i++) {
            boolean solved = Progress.isSolved(this, Challenges.ALL[i].id);
            solvedMarks[i].setVisibility(solved ? View.VISIBLE : View.GONE);
        }
    }

    private View row(final int index) {
        Challenges.Item item = Challenges.ALL[index];

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, ui.dp(18), 0, ui.dp(18));
        row.setBackground(ui.pressable(null));
        row.setClickable(true);
        row.setFocusable(true);

        TextView number = ui.label(item.number(), ui.sans(500), 13, ui.mute);
        number.setFontFeatureSettings("tnum");
        number.setPadding(0, ui.dp(8), 0, 0);
        row.addView(number, new LinearLayout.LayoutParams(ui.dp(38), ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout middle = ui.column();
        TextView title = ui.label(item.title, ui.serif(480, 28), 23, ui.ink);
        title.setLetterSpacing(-0.01f);
        middle.addView(title);
        TextView technique = ui.label(item.technique, ui.sans(400), 14.5f, ui.mute);
        technique.setLineSpacing(0, 1.1f);
        middle.addView(technique, ui.below(6));
        row.addView(middle, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        LinearLayout side = ui.column();
        side.setGravity(Gravity.END);
        side.setPadding(ui.dp(12), ui.dp(8), 0, 0);
        TextView level = ui.label("Level " + item.level, ui.sans(500), 13, ui.mute);
        level.setFontFeatureSettings("tnum");
        level.setGravity(Gravity.END);
        side.addView(level);
        TextView solved = ui.label("Solved", ui.sans(600), 13, ui.accent);
        solved.setGravity(Gravity.END);
        solved.setVisibility(View.GONE);
        side.addView(solved, ui.below(6));
        solvedMarks[index] = solved;
        row.addView(side, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        row.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(MainActivity.this, ChallengeActivity.class);
                intent.putExtra(ChallengeActivity.EXTRA_INDEX, index);
                startActivity(intent);
            }
        });
        return row;
    }

    private LinearLayout.LayoutParams ruleBelow(int topDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, ui.dp(1)));
        params.topMargin = ui.dp(topDp);
        return params;
    }
}
