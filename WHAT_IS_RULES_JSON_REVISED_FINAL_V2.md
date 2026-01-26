# What is rules.json? Complete Explanation

## ⚠️ CRITICAL: SDK REQUIREMENT

**rules.json is NOT available as a simple Dashboard export.**

**rules.json MUST be obtained using the Google SecOps SDK.**

This is fundamentally different from the CSV files, which are simple Dashboard exports.

---

## Quick Answer

**rules.json** is a JSON (JavaScript Object Notation) file that contains the complete definition of ALL detection rules in your Google SecOps environment.

**How to get it:**
- Install Google SecOps SDK
- Run a Python script that queries the SecOps API
- Script generates rules.json

**NOT obtained by:** Dashboard export, clicking buttons, or simple downloads

---

## What It Contains

### Rule Information Includes:

```json
{
  "rules": [
    {
      "name": "Rule_Name_1",
      "ruleId": "abc123def456",
      "displayName": "Brute Force Detection",
      "description": "Detects multiple failed login attempts",
      "severity": "HIGH",
      "enabled": true,
      "author": "SecOps Team",
      "created": "2024-01-15",
      "lastModified": "2025-01-10",
      "tags": ["authentication", "critical"],
      "logic": "... rule detection logic ...",
      "condition": "... rule condition logic ...",
      "category": "Authentication",
      "threatName": "Credential Access"
    },
    {
      "name": "Rule_Name_2",
      "ruleId": "xyz789uvw012",
      "displayName": "Office 365 Suspicious Activity",
      "severity": "MEDIUM",
      "enabled": false,
      "description": "..."
      // ... more fields ...
    },
    // ... more rules ...
  ]
}
```

### Typical Fields:

| Field | Example | Purpose |
|-------|---------|---------|
| **name** | "Brute_Force_Detection" | Unique rule identifier |
| **ruleId** | "abc123def456" | System ID for the rule |
| **displayName** | "Brute Force Detection" | Human-readable name |
| **description** | "Detects multiple failed..." | What the rule does |
| **severity** | "HIGH", "MEDIUM", "LOW" | Risk level |
| **enabled** | true/false | Is rule active? |
| **author** | "SecOps Team" | Who created it |
| **created** | "2024-01-15" | Creation date |
| **lastModified** | "2025-01-10" | Last update |
| **category** | "Authentication" | Rule category |
| **logic** | "count > 5" | Detection logic |
| **tags** | ["authentication", "critical"] | Labels/keywords |

---

## Why The Script Needs rules.json

### The Analysis Flow

```
RULES.JSON (Via SDK)
├─ All rules in your system (342 rules)
│  ├─ Enabled rules (325)
│  └─ Disabled rules (17)
│
├─ Compares against:
│
DETECTION_RESULTS.CSV (Dashboard Export)
├─ Rules that are TRIGGERING (245 rules)
│  └─ Rules actually detecting something
│
└─ And EVENTS (70 unmapped)
   └─ Events NOT being detected
```

### What The Script Determines:

```
Using rules.json, the script can answer:

1. "How many total rules do we have?"
   → Count all rules in rules.json

2. "Which rules are enabled vs disabled?"
   → Check "enabled" field for each rule

3. "Are all enabled rules actually working?"
   → Compare enabled rules vs rules that are triggering
   
4. "Which rules are dormant?"
   → Enabled rules with no recent triggers

5. "What's the severity distribution?"
   → Count by severity level

6. "Which rule has no detections?"
   → Find rules in rules.json but not in detection_results.csv
```

---

## Example: What The Script Discovers

### WITHOUT rules.json:

```
Script can only see:
- 245 rules are triggering
- 70 events are unmapped

That's it. Missing context.

Questions that CAN'T be answered:
❌ How many disabled rules exist?
❌ Are there rules that should be working but aren't?
❌ What rules exist but never trigger?
❌ What's the overall rule health?
❌ How complete is our detection coverage?
```

### WITH rules.json:

```
Script can see:
- 342 total rules in system
- 325 rules are enabled
- 17 rules are disabled
- 245 rules are actively triggering
- 80 enabled rules are NOT triggering (potential problem!)
- 70 events are unmapped

Questions that CAN be answered:
✅ How many disabled rules?
✅ Which enabled rules are dormant?
✅ Overall rule coverage health?
✅ Should we investigate non-triggering rules?
✅ Complete rule audit results
✅ Rules that need maintenance or deletion
```

---

## How To Get rules.json

### THE ONLY METHOD: Google SecOps SDK

**rules.json is obtained via the Google SecOps SDK, not the Dashboard.**

This requires:
- **Python 3.6+** installed
- **Google SecOps SDK** installation
- **Service account credentials** from Google Cloud Console
- **Python script** that queries the SecOps API

### Overview of the Process:

```
Step 1: Install SDK
        pip install google-cloud-securityops

Step 2: Get Credentials
        Google Cloud Console → Service Accounts
        → Create/select account → Download JSON key

Step 3: Create Python Script
        Use provided export_rules.py script

Step 4: Run Script
        python3 export_rules.py credentials.json

Step 5: Verify
        rules.json file created and ready
```

---

## Where To Get Complete Instructions

### For Quick Setup (5-10 minutes):
→ **FILE_1_RULES_JSON_REVISED.md**
- Quick overview of SDK requirement
- Option 1: Local installation
- Option 2: Backend Linux host
- Troubleshooting

### For Complete Implementation (Detailed):
→ **COMPLETE_RULES_JSON_VIA_SDK_GUIDE.md**
- Full step-by-step walkthrough
- Complete Python script (copy-paste ready)
- Google Cloud credentials setup
- Automation examples (cron, Task Scheduler)
- Comprehensive troubleshooting

### For Understanding What It Is:
→ **This document** (WHAT_IS_RULES_JSON_REVISED_FINAL.md)
- What rules.json contains
- Why the script needs it
- How it's used in analysis
- Real-world examples

---

## Real-World Example

### Your Environment Has:

**rules.json (342 rules via SDK):**
```
Brute_Force_Detection (ENABLED, HIGH)
Office365_Suspicious (ENABLED, MEDIUM)
Firewall_Anomaly (DISABLED, HIGH)
Process_Injection (ENABLED, CRITICAL)
... 338 more ...
```

**detection_results.csv (245 rules triggering via Dashboard):**
```
Brute_Force_Detection ← This rule IS triggering
Office365_Suspicious ← This rule IS triggering
Process_Injection ← This rule IS triggering
... 242 more ...
```

**Script Analysis Shows:**
```
✅ Brute_Force_Detection: ENABLED & TRIGGERING ← All good
✅ Office365_Suspicious: ENABLED & TRIGGERING ← All good
❌ Process_Injection: ENABLED but... wait, it's in the CSV!

But what about:
❓ "Firewall_Anomaly" - It's in rules.json but DISABLED
❓ "Other 97 rules" - In rules.json but not triggering!

This is valuable insight only possible with rules.json!
```

---

## Why You Need rules.json

### Without rules.json:

You're essentially blind to:
- Rules that exist but aren't working
- Disabled rules taking up space
- Coverage gaps you can't measure
- Overall system health

### With rules.json:

You can:
✅ Audit your complete rule set  
✅ Find dormant/unused rules  
✅ Identify broken rules  
✅ Plan rule maintenance  
✅ Track rule health over time  
✅ Ensure rules are properly enabled  
✅ Validate rule coverage  

---

## How The Script Uses rules.json

### Step 1: Load Rules
```
Script reads the JSON file
Extracts rule names, IDs, severity, enabled status
Builds internal index of all rules
```

### Step 2: Index Rules
```
Creates lookup table:
{
  "Brute_Force_Detection": { rule object },
  "Office365_Suspicious": { rule object },
  ...
}
```

### Step 3: Compare Against Detections
```
For each rule in rules.json:
  If rule_name in detection_results.csv:
    rule_is_triggering = True
  Else:
    rule_is_triggering = False
```

### Step 4: Generate Analysis
```
Counts and reports:
- Total rules: 342
- Enabled: 325
- Disabled: 17
- Triggering: 245
- Not triggering: 80
```

---

## Example Output

The script generates analysis like this from rules.json:

```
📊 Analysis Summary:
   Total rules in JSON: 342
   Enabled rules: 325
   Rules triggering: 245
   Enabled but not triggering: 80
   Event coverage: 57.6%
   Unmapped events: 70

Rules Not Triggering (But Enabled):
├─ Rule_1: Dormant for 30+ days
├─ Rule_2: Last triggered 15 days ago
├─ Rule_3: Never triggered
├─ Rule_4: Disabled for maintenance
└─ ... 76 more rules
```

---

## File Size

Typical rules.json file sizes:

```
Small environment:   100 rules → ~500 KB
Medium environment:  300 rules → ~2 MB
Large environment:   1000+ rules → ~5+ MB
```

---

## Security & Sensitivity

### Important Notes:

⚠️ **rules.json contains sensitive information:**
- Your detection rule logic (HOW you detect threats)
- Your security strategy and capabilities
- Rule conditions and thresholds
- Custom logic you've developed

**Security Best Practices:**
✅ Keep rules.json secure (don't share publicly)
✅ Store in secure location
✅ Restrict access to authorized users
✅ Don't commit to public repositories
✅ Delete old exports when no longer needed
✅ Treat like a security blueprint (it is!)

---

## Important Reminders

⚠️ **Fresh TODAY**
- Export rules.json TODAY before analysis
- Don't use old rules.json from previous months
- Rules change daily - export each time

⚠️ **For THIS Customer**
- Each customer has different rules
- Don't share rules.json between customers
- Use service account with appropriate access

⚠️ **Credentials Security**
- Keep credentials.json secure
- Don't share or commit to version control
- Treat like password (it's your authentication key)

⚠️ **SDK Requirement**
- rules.json is API-based (not Dashboard export)
- Python and SDK installation required
- One-time setup, per-run execution

---

## Reference Documentation

### Official Google Documentation
- **SecOps SDK Libraries:** https://docs.cloud.google.com/chronicle/docs/libraries
- **SecOps API Reference:** https://cloud.google.com/python/docs/reference/securityops/latest

### Community Guide
- **Getting Started:** https://medium.com/@thatsiemguy/getting-started-with-the-google-secops-sdk-69effdde5978

---

## Quick Decision Tree

**Asking yourself: "What do I need to do?"**

```
"I want to understand what rules.json is"
→ You're reading the right document! ✓

"I'm ready to set up rules.json"
→ Go to: FILE_1_RULES_JSON_REVISED.md (quick) OR
          COMPLETE_RULES_JSON_VIA_SDK_GUIDE.md (detailed)

"I'm implementing the analysis tool"
→ Go to: STEP_BY_STEP_GUIDE_REVISED.md
         (includes rules.json setup)

"I need to troubleshoot rules.json"
→ Go to: COMPLETE_RULES_JSON_VIA_SDK_GUIDE.md
         (comprehensive troubleshooting)
```

---

## Summary

| Aspect | Detail |
|--------|--------|
| **What** | JSON file containing all detection rules |
| **How to get** | Google SecOps SDK + Python script |
| **Format** | Valid JSON (.json) |
| **Purpose** | Audit rules, find dormant rules, measure coverage |
| **Size** | Typically 500KB - 5MB |
| **Security** | Contains sensitive security information |
| **Required?** | YES - Script won't run without it |
| **Method** | API-based (not Dashboard export) |
| **Freshness** | Export TODAY for each analysis |
| **Per Customer** | Each customer needs separate export |

---

## Next Steps

**Ready to set up rules.json?**

Choose your path:

### Quick Setup (10-15 minutes)
→ Go to: **FILE_1_RULES_JSON_REVISED.md**
- Quick reference
- Two setup options
- Troubleshooting

### Complete Setup (30-45 minutes with details)
→ Go to: **COMPLETE_RULES_JSON_VIA_SDK_GUIDE.md**
- Step-by-step walkthrough
- Complete Python script (copy-paste ready)
- Credentials setup
- Automation examples
- Full troubleshooting

### Running the Complete Analysis
→ Go to: **STEP_BY_STEP_GUIDE_REVISED.md**
- Complete workflow (all 4 files)
- Includes rules.json setup
- All steps from start to results

---

**Bottom Line: rules.json is the "inventory" of all your detection rules, obtained via the Google SecOps SDK (not Dashboard export). Without it, the analysis script can't tell you which rules exist, which are enabled, or which ones aren't working properly.**
