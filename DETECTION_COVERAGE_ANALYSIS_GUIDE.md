# Detection Coverage Analysis - Complete Step-by-Step Guide

## Overall Purpose

This process identifies **detection coverage gaps** in your security environment by comparing:
- **Raw events** ingested into your system
- **Detections** triggered by your security rules

The goal is to answer critical questions:
- *"What events are we collecting but NOT detecting?"*
- *"Which enabled rules are dormant and potentially broken?"*
- *"Where do we have blind spots in detection coverage?"*

---

## ⚠️ CRITICAL LIMITATION - Read This First

### What This Analysis DOES Show:
✅ Events occurring in your environment but NOT detected by any rule  
✅ Detection coverage gaps for actual occurring events  
✅ Rules actively triggering and detecting threats  

### What This Analysis DOES NOT Show:
❌ Enabled rules that have NO recent detections (dormant rules)  
❌ Rules that exist but never triggered in the query time window  
❌ Rules that are broken or misconfigured (silently failing)  

### The Critical Problem:

**If an enabled rule never triggers, it won't appear in the detection results.** This means you could have:
- Rules that are **broken or misconfigured** (silently failing with no alerts)
- Rules that are **enabled but never matching** (overly restrictive conditions)
- Rules that **aren't working as intended** (detection dependencies not met)
- **Security blindspots** for threats you think you're monitoring

### Real-World Example: Failed Login Rule (4625)

Your environment is generating **failed login events (4625)** in high volume, but these rules are **enabled yet showing ZERO triggers**:
- `WIN_Excessive_Account_Lockout_Multiple_Users` → ENABLED but dormant
- `WIN_Excessive_Account_Lockout_Same_User` → ENABLED but dormant

**Questions this should raise:**
- ❓ Why aren't these rules triggering despite 4625 events occurring?
- ❓ Is the rule condition too restrictive?
- ❓ Are the log sources correctly mapped in the rule?
- ❓ Is the rule actually enabled in the production environment?
- ❓ Are detection dependencies (like UDM enrichment) being met?
- ❓ Has the rule logic been accidentally disabled or modified?

**This is a RED FLAG that requires immediate investigation.**

---

# Step-by-Step Process

## Step 1: Identify Top Log Volume Sources

**Purpose:** Understand your data landscape before analyzing detections

**Function:** Quantify how much data each log type generates weekly to identify high-volume sources and understand scale

**Query:**
```YARAL_1_2_LANGUAGE
metadata.log_type != ""
$log_type = metadata.log_type
$week = timestamp.get_timestamp(metadata.event_timestamp.seconds, "WEEK", "UTC")

match:
  $log_type, $week

outcome:
  $event_count = count(metadata.id)
  $week_gigabytes = ($event_count * 1024) / (1024 * 1024 * 1024)

order:
  $log_type asc, $week desc

limit:
  10000
```

**Steps:**
1. Run this query in Google SecOps / SIEM
2. Review results (no file export needed for this step)

**Output:** 
- Log type (e.g., winevtlog, fortinet_firewall, office_365, powershell)
- Weekly event count per log type
- Weekly data volume in GB

**Why it matters:** 
- High-volume log types have more detection opportunities and potential gaps
- Low-volume types may be security-critical but easy to miss
- Helps prioritize which log types need better coverage

**Action:** Reference only (optional). Helps context for Steps 2-3.

---

## Step 2: Extract Rules and Their Detection Activity

**Purpose:** Map what your detection rules are actually catching

**Function:** List all detection rules that have triggered recently and show:
- How many times each rule has triggered
- What threats/behaviors the rule detects
- Rule severity, category, and authorship
- When the rule last triggered

⚠️ **IMPORTANT:** This query must be run in a **Dashboard**, NOT in a native query interface.

**Query:**
```YARAL_1_2_LANGUAGE
detection.detection.rule_name != ""

$rule_name = detection.detection.rule_name
$rule_description = detection.detection.description
$rule_summary = detection.detection.summary
$rule_threat = detection.detection.threat_name
$rule_severity = detection.detection.severity
$rule_category = detection.detection.category
$rule_author = detection.detection.rule_author
$update_time = detection.detection.last_updated_time.seconds

match:
  $rule_name

outcome:
  $alert_count = count_distinct(detection.id)
  $sample_descriptions = array_distinct($rule_description)
  $rule_summary_text = array_distinct($rule_summary)
  $threat_names = array_distinct($rule_threat)
  $severity_levels = array_distinct($rule_severity)
  $categories = array_distinct($rule_category)
  $authors = array_distinct($rule_author)
  $last_trigger_time = max($update_time)
  $estimated_daily_gb = math.round($alert_count * 1.5 / 1024 / 30, 2)

order:
  $alert_count asc

limit:
  1000
```

**Steps:**
1. Go to your Google SecOps **Dashboard** (not native query)
2. Create a new dashboard table or use existing table
3. Paste the query above into the dashboard query editor
4. Run the query in the dashboard
5. Export results as CSV
6. **Save as `detection_results.csv`**

**Output:**
- Rule name
- Number of alerts triggered (in query period)
- Rule description and summary
- Threat/behavior category
- Rule severity level
- Last trigger timestamp
- Estimated data volume per day
- Rules listed are ONLY those that have triggered

**Important:** 
- Rules showing 0 triggers are **NOT in this file**
- This file is what we compare against in Step 4

**Why it matters:** 
- Shows which rules are actively detecting
- Identifies which rules have been dormant
- Baseline for comparison with raw events

**Action:** 
1. Save as `detection_results.csv` (keep for Step 4)

---

## Step 3: Capture All Raw Event Data

**Purpose:** Get a complete picture of all events occurring in your environment (regardless of whether they're detected)

**Function:** Extract all raw events with their classification:
- Log type (source system: Windows logs, Fortinet, Office 365, etc.)
- Event type (behavior category: USER_LOGIN, PROCESS_LAUNCH, NETWORK_CONNECTION, etc.)
- Product event type (specific identifier: 4624, 4688, traffic-forward, etc.)

**Query:**
```YARAL_1_2_LANGUAGE
metadata.log_type != ""
principal.hostname != ""
metadata.event_type != "EVENTTYPE_UNSPECIFIED"
metadata.product_event_type != ""

$host = principal.hostname
$log_type = metadata.log_type
$event_type = metadata.event_type
$product_event_type = metadata.product_event_type
$day = timestamp.get_timestamp(metadata.event_timestamp.seconds, "DAY", "UTC")

match:
  $log_type, $event_type, $product_event_type, $day

outcome:
  $event_count = count(metadata.id)
  $host_list = array_distinct($host)

order:
  $event_count desc

limit:
  10000
```

**Steps:**
1. Run this query in Google SecOps / SIEM
2. Export results as CSV
3. **Save as `event_results.csv`**

**Output:**
- Log type (source system)
- Event type (behavior category)
- Product event type (detailed identifier)
- Daily event count
- List of hosts generating the event

**Important:** 
- This is the complete universe of events
- Includes events detected AND undetected
- Used in Step 4 for comparison

**Why it matters:** 
- Shows everything happening in your environment
- Baseline for identifying coverage gaps
- Helps prioritize which events matter most (by frequency)

**Action:** 
1. Save as `event_results.csv` (critical for Step 4)

---

## Step 4: Run Python Comparison Script

**Purpose:** Identify which events are NOT being detected

**Function:** The Python script (`compare_unmapped_events.py`) performs set comparison:
1. Load all unique (log_type, event_type, product_event_type) combinations from detections (Step 2)
2. Load all unique combinations from raw events (Step 3)
3. Find combinations in raw events but NOT in detections
4. **Result: Unmapped events** = events occurring but no rule triggered

**How it works (mathematically):**

```
Raw Events = {
  (winevtlog, USER_LOGIN, 4624),        ← Successful login
  (winevtlog, USER_LOGIN, 4625),        ← Failed login
  (fortinet_firewall, NETWORK_CONNECTION, traffic-forward),
  (office_365, USER_LOGIN, UserLoginFailed),
  ...
}

Detections = {
  (winevtlog, USER_LOGIN, 4624),        ← Has rule detecting it
  (fortinet_firewall, NETWORK_CONNECTION, traffic-forward),
  ...
}

Unmapped = Raw Events - Detections = {
  (winevtlog, USER_LOGIN, 4625),        ← Event occurs, but no rule detects it
  (office_365, USER_LOGIN, UserLoginFailed),
  ...
}
```

**Steps:**

1. Download `compare_unmapped_events.py` from outputs folder
2. Run the script:
   ```bash
   python compare_unmapped_events.py
   ```
3. When prompted:
   - Select `detection_results.csv` (from Step 2)
   - Select `event_results.csv` (from Step 3)
4. Script automatically processes files

**Automatic Output:**

**Console (terminal):**
```
Column names found: [log_type, event_type, ...]
✓ Loaded X unique combinations from detection results
✓ Loaded Y unique combinations from event results

SUMMARY STATISTICS
==================
Total unique event combinations: Z
Mapped to rules: X
NOT mapped to rules: Y
Coverage: X%
```

**Browser (automatic):**
- Opens `unmapped_events_report.html`
- Beautiful visual report with charts

**Downloads folder:**
- `unmapped_events_report.html` (saved for future reference)

---

## Step 5: Review Script Results

**Purpose:** Understand what events are not being detected

**The Report Shows:**

### Summary Cards:
- **Total Combinations**: All unique (log_type, event_type, product_event_type) pairs found in raw events
- **Mapped to Rules**: How many of those are detected by enabled rules
- **Unmapped Combinations**: Events occurring but NOT detected (potential coverage gaps)
- **Detection Coverage**: Percentage of events being detected (higher is better)

### Coverage Bar:
Visual representation of detection coverage percentage

### Detailed Tables (grouped by log type):
For each log type (winevtlog, office_365, fortinet_firewall, etc.):
- Event type (behavior category)
- Product event type (specific identifier)
- Status: "Unmapped"
- Event count

### Example Report Layout:
```
TOTAL COMBINATIONS: 165
├─ Mapped: 95 (57.6%)
├─ Unmapped: 70 (42.4%)
└─ Coverage: 57.6%

WINEVTLOG (28 unmapped events)
├─ USER_LOGIN + 4625
├─ USER_LOGIN + 4768
├─ PROCESS_LAUNCH + 4688
└─ ...

OFFICE_365 (15 unmapped events)
├─ USER_LOGIN + UserLoginFailed
├─ EMAIL_SEND + Success
└─ ...

FORTINET_FIREWALL (27 unmapped events)
├─ NETWORK_CONNECTION + traffic-local
├─ NETWORK_CONNECTION + utm-ssl
└─ ...
```

---

## Step 5.5: Categorize Results

### Three Categories of Events:

**CATEGORY 1: Unmapped Events (appear in report) ⚠️**
```
Example: winevtlog + USER_LOGIN + 4625 (Failed logon)
Status: UNMAPPED (occurring but no rule detecting)

Likely causes:
- No rule exists for this event type
- Rule is disabled in environment
- Rule condition doesn't match these events
- Rule never triggers despite correct configuration
```

**CATEGORY 2: Dormant Rules (do NOT appear in report) 🔴 CRITICAL**
```
Example: WIN_Excessive_Account_Lockout_Multiple_Users
Status: ENABLED but ZERO detections in query period

Likely causes:
- Rule is broken (syntax error, bad condition)
- Rule is misconfigured (fields don't exist, thresholds unrealistic)
- Rule conditions never match real events
- Detection enrichment/dependencies not working
- Rule disabled in production
```

**CATEGORY 3: Active Rules (appear in report) ✅**
```
Example: WIN_Excessive_Account_Lockout_Multiple_Users
Alert Count: 24 detections in period
Status: WORKING ✅

Conclusion: Rule is functioning and detecting threats
```

---

## Step 6: Manual Verification - Check Enabled Rules for Dormancy

**⚠️ THIS STEP IS CRITICAL AND REQUIRED**

The Python script identifies unmapped events, but it **cannot identify enabled rules that are broken and dormant**. You must manually check.

**Purpose:** Identify enabled rules showing zero detections that might indicate rule misconfiguration or breakage

**Process:**

### 6.1: Export All Enabled Rules from Rule Management UI

1. Go to your Security Command Center or Rule Management interface
2. Filter for: **Status = ENABLED**
3. Export/download list of all enabled rules
4. Document:
   - Rule Name
   - Status (ENABLED)
   - Category
   - Threat Type

Example list:
```
WIN_Excessive_Account_Lockout_Multiple_Users | ENABLED | Account Activity | Credential Access
WIN_Excessive_Account_Lockout_Same_User | ENABLED | Account Activity | Credential Access
WIN_Suspicious_Process_Execution | ENABLED | Process Activity | Execution
...
```

### 6.2: Cross-Reference Against detection_results.csv

1. Open `detection_results.csv` (from Step 2)
2. Extract column: `rule_name` (or similar)
3. Create list of rules that DID trigger

Example from detection_results.csv:
```
WIN_Suspicious_Process_Execution | 45 alerts
WIN_Admin_Account_Usage | 12 alerts
...
```

Notice: The two "WIN_Excessive_Account_Lockout" rules are NOT in this list

### 6.3: Identify Missing Rules

Compare the two lists:

**Enabled Rules (from Rule Management UI):**
```
1. WIN_Excessive_Account_Lockout_Multiple_Users
2. WIN_Excessive_Account_Lockout_Same_User
3. WIN_Suspicious_Process_Execution
4. WIN_Admin_Account_Usage
...
```

**Rules That Triggered (from detection_results.csv):**
```
1. WIN_Suspicious_Process_Execution
2. WIN_Admin_Account_Usage
...
```

**Missing (Dormant) Rules:**
```
1. WIN_Excessive_Account_Lockout_Multiple_Users ← ENABLED but 0 triggers
2. WIN_Excessive_Account_Lockout_Same_User ← ENABLED but 0 triggers
```

### 6.4: For Each Dormant Rule - Investigate

For each enabled rule with zero detections, investigate:

**Rule: `WIN_Excessive_Account_Lockout_Multiple_Users`**

Investigation Checklist:
- [ ] Rule is enabled in production environment? (Verify in UI)
- [ ] Rule syntax/logic is correct? (Review rule condition)
- [ ] All fields in rule condition exist in logs? (Check field mappings)
- [ ] UDM enrichment is working? (Are required fields populated?)
- [ ] Log sources configured correctly? (Are logs flowing?)
- [ ] Rule dependencies met? (Check related rules/prerequisites)
- [ ] Related events occurring? (Check for 4625 events in Step 3 results)
- [ ] Sample events match rule manually? (Run raw UDM query for 4625)
- [ ] Thresholds realistic? (Is rule too strict?)
- [ ] Rule was not recently disabled? (Check rule modification history)

**Investigation Process:**

Step 1: Verify 4625 events exist
```
From Step 3 results (event_results.csv), do you see:
✓ winevtlog + USER_LOGIN + 4625 → YES (events are occurring)
```

Step 2: Check why rule isn't triggering
```
Rule requires:
- Event type: USER_LOGIN
- Product event type: 4625
- Threshold: 5+ failed logins within 15 minutes

Possible issues:
- Threshold is 50+ (too high for your environment)
- Rule looks for "lockout" field that doesn't exist
- Rule requires additional fields not populated in UDM
- Rule hasn't seen the event pattern yet (timing issue)
```

Step 3: Determine root cause
```
✅ Rule working correctly: Events don't match threshold in your environment
❌ Rule broken: Configuration error prevents detection
❓ Rule stale: Not updated to match current UDM schema
```

### 6.5: Document Findings

Create investigation report:

```
DORMANT RULES REQUIRING ATTENTION:

Rule Name: WIN_Excessive_Account_Lockout_Multiple_Users
├─ Current Status: ENABLED
├─ Detection Activity: 0 triggers in past 30 days
├─ Related Events Occurring: YES (winevtlog + USER_LOGIN + 4625)
├─ Investigation Findings:
│  └─ Rule threshold is 50+ failed logins/hour
│  └─ Your environment averages 15-20/hour
│  └─ This is why rule never triggers
├─ Recommended Action: 
│  └─ Lower threshold to 20+ for this environment
│  └─ OR: Accept rule is too strict for your use case
└─ Status: NEEDS ADJUSTMENT

Rule Name: WIN_Excessive_Account_Lockout_Same_User
├─ Current Status: ENABLED
├─ Detection Activity: 0 triggers in past 30 days
├─ Related Events Occurring: YES (winevtlog + USER_LOGIN + 4625)
├─ Investigation Findings:
│  └─ Rule condition looks for field "user_lockout_status" 
│  └─ This field doesn't exist in current UDM schema
│  └─ Rule never matches any events
├─ Recommended Action: 
│  └─ Update rule condition to use "account_lockout_status"
│  └─ Verify all field references exist in UDM
└─ Status: BROKEN - NEEDS FIX

Rule Name: WIN_Suspicious_Process_Execution
├─ Current Status: ENABLED
├─ Detection Activity: 45 triggers in past 30 days
├─ Status: WORKING ✅ (skip this one)
```

---

## Step 7: Interpret Results - Complete Picture

### Risk Assessment Framework:

#### 🔴 HIGH PRIORITY - Create Rules or Fix Dormant Rules

**Unmapped High-Risk Events:**
- Failed login attempts (4625) - if rule is dormant
- Account modifications (4722-4728)
- Privilege escalation (4672)
- Administrative access events
- Deletion events (DELETE category)
- Access denied / permission denied

**Dormant High-Risk Rules:**
- Any rule for credential access
- Privilege escalation detection rules
- Admin account monitoring
- High-severity threat detection

**Action:** 
- Create new rules for critical unmapped events
- Fix broken dormant rules immediately
- Re-run script to verify improvements

#### 🟡 MEDIUM PRIORITY - Review and Plan

**Unmapped Medium-Risk Events:**
- User account modifications
- Application errors
- File access patterns
- Service restarts

**Dormant Medium-Risk Rules:**
- Behavior anomaly detection
- Unusual activity patterns
- Medium severity threats

**Action:**
- Schedule rule creation in next cycle
- Monitor these events manually
- Assess if rule is needed in your environment

#### 🟢 LOW PRIORITY - Optional

**Unmapped Low-Risk Events:**
- Routine process execution (4688)
- Normal file access (4663)
- Status update events
- Routine application operations (email sends, etc.)
- Normal system operations

**Dormant Low-Risk Rules:**
- Rules for non-critical events
- Rules for rare scenarios
- Rules monitoring low-threat activities

**Action:**
- Review but no immediate action needed
- Decide if rule is necessary for your environment
- Can remain unmapped/disabled if not relevant

### Key Interpretation Rules:

⚠️ **IF a critical event type (4625, 4672, etc.) is unmapped:**
- AND a rule exists for it (dormant)
- AND events are occurring
- **THEN: Rule is broken and needs investigation/fix**

⚠️ **IF a critical event type is unmapped:**
- AND no rule exists for it
- AND events are occurring
- **THEN: Need to create a new rule**

✅ **IF events are unmapped:**
- BUT no rule exists
- BUT events are low-risk/routine
- **THEN: Acceptable - no rule needed**

---

## Step 8: Next Steps & Action Plan

### 8.1: For Unmapped High-Risk Events (from Python script results)

**Process:**
1. Review `unmapped_events_report.html` results
2. Identify high-risk unmapped events (see Step 7 risk assessment)
3. For each critical event:
   - Determine if a rule should exist
   - Create new rule if needed
   - Test rule with sample events

**Example:**
```
Finding: winevtlog + USER_LOGIN + 4625 is unmapped
├─ 4625 = Failed logon (high-risk)
├─ Events occurring: YES (1200+ per day)
├─ Rule should exist: YES
├─ Action: Create new rule "WIN_Failed_Login_Threshold"
└─ Timeline: This sprint
```

### 8.2: For Dormant Rules (manual verification)

**Process:**
1. Review your enabled rules list
2. Cross-reference with detection_results.csv
3. Investigate any enabled rule with 0 detections
4. Categorize:
   - **Rule is broken**: Fix rule configuration
   - **Rule is correct but doesn't match**: Adjust threshold or conditions
   - **Rule is not relevant**: Disable rule if not needed

**Example:**
```
Finding: WIN_Excessive_Account_Lockout_Multiple_Users is dormant
├─ Status: ENABLED
├─ Detections: 0 in 30 days
├─ Investigation: Threshold 50+/hour, events 15-20/hour
├─ Root Cause: Threshold too high for environment
├─ Action: Adjust threshold to 20+ failed logins/hour
└─ Timeline: This week
```

### 8.3: For Dormant Rules with Broken Logic (manual verification)

**Process:**
1. Identify rules with field mapping errors (from investigation)
2. Update rule condition to match current UDM schema
3. Test rule with sample events
4. Verify detections start appearing

**Example:**
```
Finding: WIN_Excessive_Account_Lockout_Same_User is dormant
├─ Status: ENABLED
├─ Detections: 0 in 30 days
├─ Investigation: Field "user_lockout_status" doesn't exist in UDM
├─ Root Cause: Rule condition outdated - schema changed
├─ Action: Update rule to use "account.lock_status" field
└─ Timeline: This week - critical fix
```

### 8.4: Re-Test After Changes

After creating new rules or fixing dormant rules:

1. Wait 24-48 hours for rule to trigger on new events
2. Run Steps 2-4 again with fresh data
3. Verify:
   - Previously unmapped events now have rules
   - Previously dormant rules are now triggering
   - Coverage percentage improved
4. Document improvements:
   ```
   Coverage Improvement Report:
   ├─ Before: 57.6% coverage (95 mapped / 165 total)
   ├─ After: 72.3% coverage (119 mapped / 165 total)
   ├─ Improvement: +14.7%
   ├─ Rules Created: 5
   ├─ Rules Fixed: 3
   └─ Remaining Gaps: 46 unmapped (mostly low-risk)
   ```

### 8.5: Establish Ongoing Monitoring

Create a regular cadence:

**Monthly:**
- Run detection coverage analysis script
- Review for new unmapped events
- Check dormant rules don't exceed threshold

**Quarterly:**
- Comprehensive rule audit
- Review coverage improvements
- Plan rule creation/updates for next quarter

**As-Needed:**
- When new log sources added → run analysis
- When rule changes made → verify impact
- When threat landscape changes → review coverage

---

## Complete Workflow Summary

```
START: Understand Detection Coverage

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 1: Run Log Volume Query (optional reference)      │
│ → Understand scale and frequency of events             │
│ → No export needed                                      │
└─────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 2: Export Detection Rules Query                   │
│ → What rules are actively detecting                    │
│ → Export as detection_results.csv                      │
└─────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 3: Export Raw Events Query                        │
│ → All events occurring in environment                  │
│ → Export as event_results.csv                          │
└─────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 4: Run Python Comparison Script                   │
│ → Identifies unmapped events                           │
│ → Generates HTML report                                │
│ → Shows coverage percentage                            │
└─────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 5: Review Script Results                          │
│ → Analyze unmapped events report                       │
│ → Identify high-risk gaps                              │
│ → Categorize events by risk level                      │
└─────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 6: Manual Verification (CRITICAL) ⚠️             │
│ → Export enabled rules from UI                         │
│ → Cross-reference with detection_results.csv           │
│ → Identify dormant rules (0 triggers)                  │
│ → Investigate why dormant rules aren't triggering      │
│ → Determine if broken or not applicable                │
└─────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 7: Interpret Results                              │
│ → High-risk unmapped events                            │
│ → High-risk dormant rules                              │
│ → Medium-risk gaps                                     │
│ → Low-risk events (acceptable unmapped)                │
└─────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 8: Create Action Plan                             │
│                                                         │
│ For Unmapped Events:                                    │
│ ├─ Create new rules for high-risk gaps                 │
│ ├─ Test rules with sample events                       │
│ └─ Schedule implementation                             │
│                                                         │
│ For Dormant Rules:                                      │
│ ├─ Fix broken rule logic                               │
│ ├─ Adjust thresholds/conditions                        │
│ ├─ Update field mappings                               │
│ └─ Test and verify                                     │
│                                                         │
│ Timeline: Prioritize critical items this sprint        │
└─────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 9: Re-Test After Changes (24-48 hours)           │
│ → Run Steps 2-4 again with fresh data                  │
│ → Verify unmapped events now detected                  │
│ → Verify dormant rules now triggering                  │
│ → Measure coverage improvement                         │
└─────────────────────────────────────────────────────────┘

    ↓

┌─────────────────────────────────────────────────────────┐
│ STEP 10: Establish Ongoing Monitoring                  │
│ → Monthly: Run analysis for trend analysis             │
│ → Quarterly: Comprehensive rule audit                  │
│ → As-needed: New log sources, rule changes             │
└─────────────────────────────────────────────────────────┘

    ↓

END: Continuous Detection Coverage Improvement
```

---

## Queries Reference

### Query 1: Log Volume by Week
```YARAL_1_2_LANGUAGE
metadata.log_type != ""
$log_type = metadata.log_type
$week = timestamp.get_timestamp(metadata.event_timestamp.seconds, "WEEK", "UTC")
match:
  $log_type, $week
outcome:
  $event_count = count(metadata.id)
  $week_gigabytes = ($event_count * 1024) / (1024 * 1024 * 1024)
order:
  $log_type asc, $week desc
limit:
  10000
```

### Query 2: Detection Rules Activity (EXPORT AS detection_results.csv)
```YARAL_1_2_LANGUAGE
detection.detection.rule_name != ""

$rule_name = detection.detection.rule_name
$rule_description = detection.detection.description
$rule_summary = detection.detection.summary
$rule_threat = detection.detection.threat_name
$rule_severity = detection.detection.severity
$rule_category = detection.detection.category
$rule_author = detection.detection.rule_author
$update_time = detection.detection.last_updated_time.seconds

match:
  $rule_name

outcome:
  $alert_count = count_distinct(detection.id)
  $sample_descriptions = array_distinct($rule_description)
  $rule_summary_text = array_distinct($rule_summary)
  $threat_names = array_distinct($rule_threat)
  $severity_levels = array_distinct($rule_severity)
  $categories = array_distinct($rule_category)
  $authors = array_distinct($rule_author)
  $last_trigger_time = max($update_time)
  $estimated_daily_gb = math.round($alert_count * 1.5 / 1024 / 30, 2)

order:
  $alert_count asc

limit:
  1000
```

### Query 3: Raw Events Data (EXPORT AS event_results.csv)
```YARAL_1_2_LANGUAGE
metadata.log_type != ""
principal.hostname != ""
metadata.event_type != "EVENTTYPE_UNSPECIFIED"
metadata.product_event_type != ""

$host = principal.hostname
$log_type = metadata.log_type
$event_type = metadata.event_type
$product_event_type = metadata.product_event_type
$day = timestamp.get_timestamp(metadata.event_timestamp.seconds, "DAY", "UTC")

match:
  $log_type, $event_type, $product_event_type, $day

outcome:
  $event_count = count(metadata.id)
  $host_list = array_distinct($host)

order:
  $event_count desc

limit:
  10000
```

---

## Tools Reference

### Python Script: compare_unmapped_events.py

**Location:** `/mnt/user-data/outputs/compare_unmapped_events.py`

**Function:** Compares detection results against raw events to identify coverage gaps

**Usage:**
```bash
python compare_unmapped_events.py
```

**Inputs:**
- `detection_results.csv` (from Query 2)
- `event_results.csv` (from Query 3)

**Outputs:**
- Console: Summary statistics
- Browser: `unmapped_events_report.html` (visual report)
- Downloads: `unmapped_events_report.html` (saved copy)

**Requirements:**
- Python 3.6+
- tkinter (included with Python)
- CSV files from Steps 2-3

---

## Key Takeaways

### The Three Critical Findings:

1. **Unmapped Events (from script):**
   - Events occurring in your environment
   - NOT detected by any rule
   - May indicate missing rules or misconfigured rules
   - High-risk ones need investigation/remediation

2. **Dormant Rules (manual verification):**
   - Rules that are ENABLED
   - Show 0 detections in query period
   - Strong indicator of rule misconfiguration/breakage
   - MUST be investigated - they represent blind spots

3. **Active Rules (from script):**
   - Rules actively triggering
   - Providing detection coverage
   - Baseline for comparison

### Critical Success Factor:

> **You MUST perform Step 6 (manual verification) to find dormant rules. The Python script alone is incomplete. An enabled rule with zero detections despite matching events is a RED FLAG requiring immediate investigation.**

### Example: Failed Login Accountability

```
Scenario: You see 4625 events (failed login) in the report as UNMAPPED

BUT ALSO: You have rules enabled:
- WIN_Excessive_Account_Lockout_Multiple_Users
- WIN_Excessive_Account_Lockout_Same_User

Questions:
Q1: Are these rules in detection_results.csv?
  └─ NO → Rules are dormant (not triggering)

Q2: Are 4625 events occurring?
  └─ YES → Events are in event_results.csv

Conclusion: Rules are broken or misconfigured
  └─ They should be detecting 4625 events
  └─ They're enabled but not working
  └─ THIS IS A SECURITY BLIND SPOT

Action Required:
  └─ Investigate why rules aren't triggering
  └─ Fix rule logic or configuration
  └─ Verify they start detecting after fix
```

---

## Checklist for Execution

### Before You Start:
- [ ] Access to Google SecOps / SIEM query interface
- [ ] Export permissions for CSV
- [ ] Python 3.6+ installed locally
- [ ] Text editor for reviewing CSVs
- [ ] Access to Rule Management UI for Step 6

### Step 2 - Detection Rules:
- [ ] Query runs successfully
- [ ] Results show rule names and trigger counts
- [ ] Export to CSV as `detection_results.csv`
- [ ] File contains 50+ rule names (verify not empty)

### Step 3 - Raw Events:
- [ ] Query runs successfully
- [ ] Results show log_type, event_type, product_event_type
- [ ] Export to CSV as `event_results.csv`
- [ ] File contains 100+ combinations (verify not empty)

### Step 4 - Python Script:
- [ ] Script runs without errors
- [ ] Browser opens with HTML report
- [ ] Report shows summary statistics
- [ ] Coverage percentage displayed

### Step 5 - Script Review:
- [ ] Identify unmapped events
- [ ] Assess risk of each unmapped event
- [ ] Note high-risk gaps requiring action

### Step 6 - Manual Verification:
- [ ] Export enabled rules from Rule Management UI
- [ ] Compare against detection_results.csv
- [ ] Identify dormant rules (enabled but 0 triggers)
- [ ] Investigate each dormant rule
- [ ] Document root causes and actions

### Step 8 - Action Plan:
- [ ] List high-risk unmapped events needing rules
- [ ] List dormant rules needing fixes
- [ ] Assign priorities (critical, high, medium, low)
- [ ] Schedule implementation timeline
- [ ] Assign owners

### Step 9 - Verification:
- [ ] Wait 24-48 hours for new detections
- [ ] Re-run Steps 2-4 with fresh data
- [ ] Measure coverage improvement
- [ ] Document before/after metrics

---

## Glossary

**Detection:** A security event that triggered an alert from an enabled rule

**Unmapped Event:** An event occurring in your logs but not detected by any rule

**Dormant Rule:** A rule that is enabled but showing zero triggers (not detecting anything)

**Coverage:** Percentage of events being detected by rules (mapped / total)

**Event Type:** Behavioral category (USER_LOGIN, PROCESS_LAUNCH, etc.)

**Product Event Type:** Specific event identifier (4625, 4688, traffic-forward, etc.)

**Log Type:** Source system (winevtlog, fortinet_firewall, office_365, etc.)

**UDM:** Unified Detection Model - normalized event format in Google SecOps

---

## Support & Questions

**For Python Script Issues:**
- Check console output for column names
- Verify CSV files exported correctly
- Ensure file names match expected columns

**For Query Issues:**
- Check syntax against YARAL documentation
- Verify field names exist in your environment
- Test with smaller time ranges first

**For Rule Investigation:**
- Verify rule conditions are correct syntax
- Check all fields exist in current UDM schema
- Compare rule against sample events manually
- Review rule modification history

---

## Document Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Jan 15, 2026 | Initial release with dormant rule identification |
| | | Added Step 6 for manual rule verification |
| | | Added critical limitation section |
| | | Added investigation checklist |

---

**Last Updated:** January 15, 2026  
**Maintainer:** Security Operations Team
