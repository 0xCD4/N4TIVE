package com.ctf.nativectf;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends Activity {

    // Challenge Data: ID, Name, Diff, Hint, Hex Address (cosmetic)
    private static final String[][] CHALLENGES = {
        {"ch01", "STRING MAZE",       "Lv.1", "Strings hide behind layers.", "0x00401000"},
        {"ch02", "STACK SMASHER",     "Lv.2", "Buffer overflow mechanics.",  "0x004020A0"},
        {"ch03", "TYPE CONFUSION",    "Lv.3", "JNI pointer mismatch.",       "0x004031B8"},
        {"ch04", "ANTI-DEBUG",        "Lv.3", "Seven locks guard the door.", "0x004045C0"},
        {"ch05", "HEAP FENG SHUI",    "Lv.4", "UAF & Heap manipulation.",    "0x00405D40"},
        {"ch06", "VIRTUAL MACHINE",   "Lv.5", "Custom bytecode arch.",       "0x00406F00"},
    };

    // Hardware Theme Colors
    private static final int BG_COLOR = Color.parseColor("#090C10"); // Deep dark
    private static final int TEXT_PRIMARY = Color.parseColor("#C9D1D9");
    private static final int TEXT_DIM = Color.parseColor("#484F58");
    private static final int ACCENT_CYAN = Color.parseColor("#58A6FF"); // Blue/Cyan
    private static final int ACCENT_GREEN = Color.parseColor("#3FB950"); // Matrix/Success Green
    private static final int BORDER_COLOR = Color.parseColor("#30363D");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG_COLOR);
        
        // Header Section (Terminal Boot Style)
        root.addView(createTerminalHeader());

        // Scroll Area
        ScrollView scroll = new ScrollView(this);
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        scroll.setLayoutParams(scrollParams);
        
        LinearLayout list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        list.setPadding(32, 24, 32, 24);

        for (int i = 0; i < CHALLENGES.length; i++) {
            list.addView(createHardwareCard(i));
        }
        
        // Add a fake "memory dump" footer inside scroll
        TextView memDump = new TextView(this);
        memDump.setText("\n>> END OF MEMORY SEGMENT\n>> WAITING FOR INPUT_");
        memDump.setTypeface(Typeface.MONOSPACE);
        memDump.setTextColor(Color.parseColor("#21262D"));
        memDump.setTextSize(10);
        memDump.setGravity(Gravity.CENTER);
        memDump.setPadding(0, 32, 0, 64);
        list.addView(memDump);

        scroll.addView(list);
        root.addView(scroll);

        // Fixed Footer Signature
        root.addView(createSignatureFooter());

        setContentView(root);
    }

    private View createTerminalHeader() {
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.VERTICAL);
        header.setPadding(48, 64, 48, 32);
        header.setGravity(Gravity.CENTER);

        // Logo removed
        /*
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.ic_logo_cpu);
        logo.setColorFilter(ACCENT_CYAN); // Tint the logo cyan
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(160, 160);
        lp.bottomMargin = 24;
        logo.setLayoutParams(lp);
        header.addView(logo);
        */

        // System Text

        TextView sysText = new TextView(this);
        sysText.setText("// SYSTEM: ONLINE\n// ARCH: ARM64-v8a");
        sysText.setTextColor(ACCENT_GREEN);
        sysText.setTypeface(Typeface.MONOSPACE);
        sysText.setTextSize(12);
        sysText.setGravity(Gravity.CENTER);
        header.addView(sysText);

        // Title
        TextView title = new TextView(this);
        title.setText("N4TIVE");
        title.setTextColor(TEXT_PRIMARY);
        title.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        title.setTextSize(20);
        title.setPadding(0, 16, 0, 0);
        header.addView(title);

        return header;
    }

    private View createHardwareCard(final int index) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        
        // Custom "Tech" background provided programmatically
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.parseColor("#0D1117")); // Module BG
        bg.setStroke(2, BORDER_COLOR);
        bg.setCornerRadius(8); // Slight round, almost sharp
        card.setBackground(bg);
        
        card.setPadding(32, 24, 32, 24);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = 24;
        card.setLayoutParams(params);

        // Top Row: Address | Difficulty
        LinearLayout metaRow = new LinearLayout(this);
        metaRow.setOrientation(LinearLayout.HORIZONTAL);
        
        TextView address = new TextView(this);
        address.setText(CHALLENGES[index][4]); // Hex address
        address.setTextColor(Color.parseColor("#8B949E"));
        address.setTypeface(Typeface.MONOSPACE);
        address.setTextSize(11);
        metaRow.addView(address);
        
        View spacer = new View(this);
        spacer.setLayoutParams(new LinearLayout.LayoutParams(0, 0, 1f));
        metaRow.addView(spacer);
        
        TextView diff = new TextView(this);
        diff.setText("[" + CHALLENGES[index][2] + "]");
        diff.setTextColor(getDiffColor(index));
        diff.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        diff.setTextSize(12);
        metaRow.addView(diff);
        
        card.addView(metaRow);

        // Main Title
        TextView name = new TextView(this);
        name.setText(CHALLENGES[index][1]);
        name.setTextColor(TEXT_PRIMARY);
        name.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        name.setTextSize(16);
        name.setPadding(0, 8, 0, 4);
        card.addView(name);

        // Hint (Comment style)
        TextView hint = new TextView(this);
        hint.setText("// " + CHALLENGES[index][3]);
        hint.setTextColor(Color.parseColor("#484F58")); // Comment gray
        hint.setTypeface(Typeface.MONOSPACE, Typeface.ITALIC);
        hint.setTextSize(12);
        card.addView(hint);

        // Interaction
        card.setClickable(true);
        card.setFocusable(true);
        card.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, ChallengeActivity.class);
                intent.putExtra("challenge_index", index);
                intent.putExtra("challenge_id", CHALLENGES[index][0]);
                intent.putExtra("challenge_name", CHALLENGES[index][1]);
                startActivity(intent);
            }
        });

        return card;
    }

    private View createSignatureFooter() {
        LinearLayout footer = new LinearLayout(this);
        footer.setOrientation(LinearLayout.VERTICAL);
        footer.setBackgroundColor(Color.parseColor("#050709")); // Slightly darker
        footer.setPadding(0, 32, 0, 48);
        footer.setGravity(Gravity.CENTER); // Ensure centering

        // Separator Line
        View line = new View(this);
        line.setBackgroundColor(Color.parseColor("#30363D")); // Lighter grey line
        LinearLayout.LayoutParams lineParams = new LinearLayout.LayoutParams(120, 4); // Thicker line
        lineParams.bottomMargin = 24;
        line.setLayoutParams(lineParams);
        footer.addView(line);

        TextView sig = new TextView(this);
        sig.setText("Built by Ahmet Göker");
        sig.setTextColor(Color.WHITE); // Pure White
        sig.setTypeface(Typeface.MONOSPACE, Typeface.BOLD); // BOLD
        sig.setTextSize(13); // Slightly larger
        sig.setGravity(Gravity.CENTER);
        sig.setLetterSpacing(0.05f);
        
        footer.addView(sig);

        return footer;
    }

    private int getDiffColor(int index) {
        if (index < 2) return ACCENT_GREEN;
        if (index < 4) return ACCENT_CYAN;
        return Color.parseColor("#FF7B72"); // Soft Red
    }
}
