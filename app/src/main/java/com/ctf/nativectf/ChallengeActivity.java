package com.ctf.nativectf;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.ctf.nativectf.challenges.*;

/**
 * Individual challenge screen with flag submission.
 */
public class ChallengeActivity extends Activity {

    private int challengeIndex;
    private String challengeId;
    private String challengeName;
    private TextView statusText;
    private EditText flagInput;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        challengeIndex = getIntent().getIntExtra("challenge_index", 0);
        challengeId = getIntent().getStringExtra("challenge_id");
        challengeName = getIntent().getStringExtra("challenge_name");

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.parseColor("#0D1117"));

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 48, 48, 48);

        // Back button
        TextView back = new TextView(this);
        back.setText("< Back");
        back.setTextColor(Color.parseColor("#58A6FF"));
        back.setTextSize(16);
        back.setPadding(0, 0, 0, 24);
        back.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) { finish(); }
        });
        root.addView(back);

        // Title
        TextView title = new TextView(this);
        title.setText(challengeId + " - " + challengeName);
        title.setTextColor(Color.parseColor("#C9D1D9"));
        title.setTextSize(24);
        title.setPadding(0, 0, 0, 8);
        root.addView(title);

        // Library info
        TextView libInfo = new TextView(this);
        libInfo.setText("Library: lib" + challengeId + "_" + getLibSuffix() + ".so");
        libInfo.setTextColor(Color.parseColor("#8B949E"));
        libInfo.setTextSize(14);
        libInfo.setPadding(0, 0, 0, 32);
        root.addView(libInfo);

        // Description
        TextView desc = new TextView(this);
        desc.setText(getDescription());
        desc.setTextColor(Color.parseColor("#C9D1D9"));
        desc.setTextSize(14);
        desc.setLineSpacing(4, 1.2f);
        desc.setPadding(0, 0, 0, 32);
        root.addView(desc);

        // Status
        statusText = new TextView(this);
        statusText.setText("Status: UNSOLVED");
        statusText.setTextColor(Color.parseColor("#F85149"));
        statusText.setTextSize(16);
        statusText.setPadding(0, 0, 0, 24);
        root.addView(statusText);

        // Flag input
        flagInput = new EditText(this);
        flagInput.setHint("FLAG{...}");
        flagInput.setTextColor(Color.parseColor("#C9D1D9"));
        flagInput.setHintTextColor(Color.parseColor("#484F58"));
        flagInput.setBackgroundColor(Color.parseColor("#21262D"));
        flagInput.setPadding(24, 24, 24, 24);
        flagInput.setTextSize(16);
        root.addView(flagInput);

        // Submit button
        Button submit = new Button(this);
        submit.setText("SUBMIT FLAG");
        submit.setTextColor(Color.parseColor("#0D1117"));
        submit.setBackgroundColor(Color.parseColor("#238636"));

        LinearLayout.LayoutParams btnParams = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        );
        btnParams.setMargins(0, 24, 0, 0);
        submit.setLayoutParams(btnParams);

        submit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                submitFlag();
            }
        });
        root.addView(submit);

        // Interactive buttons for challenges that have them
        addChallengeButtons(root);

        scroll.addView(root);
        setContentView(scroll);
    }

    private void submitFlag() {
        String input = flagInput.getText().toString().trim();
        if (input.isEmpty()) {
            Toast.makeText(this, "Enter a flag", Toast.LENGTH_SHORT).show();
            return;
        }

        boolean correct = false;
        try {
            switch (challengeIndex) {
                case 0: correct = new Ch01().verifyFlag(input); break;
                case 1: correct = new Ch02().verifyFlag(input); break;
                case 2: correct = new Ch03().verifyFlag(input); break;
                case 3: correct = new Ch04().verifyFlag(input); break;
                case 4: correct = new Ch05().verifyFlag(input); break;
                case 5: correct = new Ch06().verifyFlag(input); break;
            }
        } catch (Exception e) {
            Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
            return;
        }

        if (correct) {
            statusText.setText("Status: SOLVED");
            statusText.setTextColor(Color.parseColor("#3FB950"));
            Toast.makeText(this, "Correct! Challenge solved.", Toast.LENGTH_LONG).show();
        } else {
            statusText.setText("Status: WRONG FLAG");
            statusText.setTextColor(Color.parseColor("#F85149"));
            Toast.makeText(this, "Wrong flag. Keep digging.", Toast.LENGTH_SHORT).show();
        }
    }

    private void addChallengeButtons(LinearLayout root) {
        LinearLayout.LayoutParams btnParams = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        );
        btnParams.setMargins(0, 16, 0, 0);

        switch (challengeIndex) {
            case 0: {
                Button tryBtn = new Button(this);
                tryBtn.setText("Run solve()");
                tryBtn.setLayoutParams(btnParams);
                tryBtn.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        try {
                            String result = new Ch01().solve();
                            Toast.makeText(ChallengeActivity.this,
                                "Result: " + result, Toast.LENGTH_LONG).show();
                        } catch (Exception e) {
                            Toast.makeText(ChallengeActivity.this,
                                "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
                        }
                    }
                });
                root.addView(tryBtn);
                break;
            }
            case 3: {
                Button checkBtn = new Button(this);
                checkBtn.setText("Run Anti-Debug Check");
                checkBtn.setLayoutParams(btnParams);
                checkBtn.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        try {
                            int status = new Ch04().checkStatus(ChallengeActivity.this);
                            StringBuilder sb = new StringBuilder("Checks: ");
                            String[] names = {"TracerPid", "Frida", "Ptrace",
                                              "Timing", "Breakpoints", "JavaDbg", "Signature"};
                            for (int i = 0; i < 7; i++) {
                                sb.append(names[i]).append("=");
                                sb.append(((status >> i) & 1) == 1 ? "PASS" : "FAIL");
                                if (i < 6) sb.append(", ");
                            }
                            Toast.makeText(ChallengeActivity.this,
                                sb.toString(), Toast.LENGTH_LONG).show();
                        } catch (Exception e) {
                            Toast.makeText(ChallengeActivity.this,
                                "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
                        }
                    }
                });
                root.addView(checkBtn);
                break;
            }
        }
    }

    private String getLibSuffix() {
        String[] suffixes = {"stringmaze", "stacksmasher", "typeconfusion",
                             "gauntlet", "heapcraft", "vm"};
        return (challengeIndex >= 0 && challengeIndex < suffixes.length)
            ? suffixes[challengeIndex] : "unknown";
    }

    private String getDescription() {
        switch (challengeIndex) {
            case 0: return "The flag is encrypted with three layers of obfuscation "
                + "inside the native library. Reverse the decryption chain to recover it.\n\n"
                + "Interface: solve() returns a partial hint.\n"
                + "Tools: Ghidra, IDA -- trace the XOR/permutation chain in .rodata.";

            case 1: return "The processInput() function has a 64-byte stack buffer "
                + "with no bounds checking. Overflow it to hijack a function pointer "
                + "that sits right after the buffer on the stack.\n\n"
                + "Interface: processInput(byte[]) -- send more than 64 bytes.\n"
                + "Target: Redirect execution to the hidden compute_secret() function.";

            case 2: return "Four gates protect the flag. Each gate has a JNI type "
                + "confusion vulnerability -- pass the wrong Java type to trigger "
                + "an alternate code path that leaks a key fragment.\n\n"
                + "Interface: gate1-4() with crafted objects, then combine().\n"
                + "Tools: Frida to call native functions with wrong parameter types.";

            case 3: return "Seven anti-analysis checks must all pass (or be bypassed) "
                + "to reveal the flag. Each check contributes a key byte.\n\n"
                + "Checks: TracerPid, Frida maps, ptrace, timing, breakpoint scan, "
                + "Java debugger, APK signature.\n"
                + "Tools: Frida hooks to force-return expected values, or binary patch.";

            case 4: return "Custom slab allocator with 8 slots. An off-by-16 overflow "
                + "in edit() lets you corrupt adjacent slot metadata. Combined with "
                + "a UAF from improperly cleared freed slots, you can hijack a "
                + "function pointer to reach the hidden flag_generator().\n\n"
                + "Interface: allocate/release/edit/read via JNI.";

            case 5: return "A custom stack-based VM with 32 instructions executes a "
                + "bytecode program (XOR-encoded in the binary). The program takes "
                + "16 bytes of input, transforms them, and checks against expected "
                + "constants.\n\n"
                + "Steps: Reverse the instruction set, decode the bytecode, "
                + "disassemble the program, solve the constraint system (Z3 recommended).";

            default: return "";
        }
    }
}
