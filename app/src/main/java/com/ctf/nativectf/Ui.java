package com.ctf.nativectf;

import android.app.Activity;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.util.SparseArray;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * The small visual vocabulary both screens share: the palette, the two
 * typefaces, rules and buttons. Colours come from resources, so the dark
 * theme follows the system setting.
 */
final class Ui {
    private static final SparseArray<Typeface> FACES = new SparseArray<>();

    final Activity activity;
    final int paper;
    final int sunken;
    final int ink;
    final int mute;
    final int line;
    final int accent;
    private final float density;
    private final boolean night;

    Ui(Activity activity) {
        this.activity = activity;
        density = activity.getResources().getDisplayMetrics().density;
        paper = activity.getColor(R.color.paper);
        sunken = activity.getColor(R.color.sunken);
        ink = activity.getColor(R.color.ink);
        mute = activity.getColor(R.color.mute);
        line = activity.getColor(R.color.line);
        accent = activity.getColor(R.color.accent);
        int mode = activity.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        night = mode == Configuration.UI_MODE_NIGHT_YES;
    }

    int dp(float value) {
        return Math.round(value * density);
    }

    /** Newsreader at a weight and optical size. Large sizes want a large optical size. */
    Typeface serif(int weight, int opticalSize) {
        return face("fonts/newsreader.ttf", 1, weight, opticalSize, Typeface.SERIF);
    }

    /** Schibsted Grotesk at a weight. */
    Typeface sans(int weight) {
        return face("fonts/schibsted_grotesk.ttf", 2, weight, 0, Typeface.SANS_SERIF);
    }

    /** Both files are variable fonts, so one file serves every weight. */
    private Typeface face(String asset, int family, int weight, int opticalSize, Typeface fallback) {
        int key = family << 20 | weight << 6 | opticalSize;
        Typeface cached = FACES.get(key);
        if (cached != null) return cached;

        String axes = "'wght' " + weight + (opticalSize > 0 ? ", 'opsz' " + opticalSize : "");
        Typeface built = null;
        try {
            built = new Typeface.Builder(activity.getAssets(), asset)
                    .setFontVariationSettings(axes)
                    .build();
        } catch (RuntimeException ignored) {
            // falls through to the system face
        }
        if (built == null) built = fallback;
        FACES.put(key, built);
        return built;
    }

    TextView label(CharSequence text, Typeface face, float sp, int color) {
        TextView view = new TextView(activity);
        view.setText(text);
        view.setTypeface(face);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        view.setTextColor(color);
        view.setIncludeFontPadding(false);
        return view;
    }

    /** A horizontal rule. The strong one is ink, the hairline is the line colour. */
    View rule(int color) {
        View view = new View(activity);
        view.setBackgroundColor(color);
        view.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, dp(1))));
        return view;
    }

    LinearLayout column() {
        LinearLayout layout = new LinearLayout(activity);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    LinearLayout.LayoutParams below(int topDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(topDp);
        return params;
    }

    /** A filled or outlined rectangle with the small radius the site uses. */
    GradientDrawable box(int fill, int stroke) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(fill);
        shape.setCornerRadius(dp(4));
        if (stroke != Color.TRANSPARENT) shape.setStroke(Math.max(1, dp(1)), stroke);
        return shape;
    }

    /** Adds touch feedback on top of a background, or on its own for plain rows. */
    Drawable pressable(Drawable content) {
        ColorStateList ripple = ColorStateList.valueOf((ink & 0x00FFFFFF) | 0x24000000);
        Drawable mask = content == null ? new ColorDrawable(Color.WHITE) : null;
        return new RippleDrawable(ripple, content, mask);
    }

    /** The one solid action on a screen. */
    TextView primaryButton(String text) {
        TextView button = label(text, sans(600), 16, paper);
        button.setBackground(pressable(box(ink, Color.TRANSPARENT)));
        return finishButton(button);
    }

    /** Secondary actions are outlined. */
    TextView secondaryButton(String text) {
        TextView button = label(text, sans(500), 16, ink);
        button.setBackground(pressable(box(Color.TRANSPARENT, ink)));
        return finishButton(button);
    }

    private TextView finishButton(TextView button) {
        button.setGravity(Gravity.CENTER);
        button.setMinHeight(dp(52));
        button.setPadding(dp(16), dp(14), dp(16), dp(14));
        button.setClickable(true);
        button.setFocusable(true);
        return button;
    }

    /** System bars take the paper colour, with dark icons in the light theme. */
    void systemBars() {
        Window window = activity.getWindow();
        window.setStatusBarColor(paper);
        window.setNavigationBarColor(paper);
        int flags = night ? 0
                : View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        window.getDecorView().setSystemUiVisibility(flags);
    }
}
