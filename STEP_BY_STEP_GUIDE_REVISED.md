# Complete Step-by-Step Guide: Google SecOps Rule Analysis Tool

## ⚠️ CRITICAL REQUIREMENT - READ FIRST

**All data files MUST be freshly exported TODAY for EACH customer and EACH analysis run.**

```
DO NOT:
  ❌ Reuse files from previous months
  ❌ Reuse files from other customers  
  ❌ Use cached/archived exports
  ❌ Mix files from different time periods

MUST:
  ✅ Export TODAY (or yesterday at latest)
  ✅ For THIS customer specifically
  ✅ All 4 files together
  ✅ From current systems
  ✅ Same date/time period
```

**Using stale or mismatched files produces INACCURATE ANALYSIS and WRONG CONCLUSIONS.**

---

## 📋 Table of Contents

1. [What This Tool Does](#what-this-tool-does)
2. [File Requirements](#file-requirements)
3. [Step 1: Download JSON Rules File](#step-1-download-json-rules-file)
4. [Step 2: Download Detection Results CSV](#step-2-download-detection-results-csv)
5. [Step 3: Download Event Results CSV](#step-3-download-event-results-csv)
6. [Step 4: Download Log Volume CSV (Optional)](#step-4-download-log-volume-csv-optional)
7. [Step 5: Verify Your Files](#step-5-verify-your-files)
8. [Step 6: Run the Python Script](#step-6-run-the-python-script)
9. [Step 7: Review the HTML Report](#step-7-review-the-html-report)
10. [Step 8: Interpret Your Results](#step-8-interpret-your-results)
11. [Troubleshooting](#troubleshooting)

---

## What This Tool Does

### The Problem

Security teams need to know:
- ❓ Do we have all the detection rules we need?
- ❓ Which rules are actually working?
- ❓ Which events are NOT being detected?
- ❓ How complete is our detection coverage?

### The Solution

This tool analyzes three data sources to answer these questions:

```
Detection Rules (What we've built)
           ↓
     COMPARE
           ↓
Detection Results (What's triggering)
           ↓
     COMPARE
           ↓
Events (What's actually happening)

Result: Complete gap analysis
```

### What You Get

An HTML report showing:
- ✅ Total rules in your system
- ✅ Which rules are enabled/disabled
- ✅ Which rules are actively triggering
- ✅ Which rules aren't working
- ✅ What events are being detected
- ✅ What events are NOT being detected (gaps)
- ✅ Overall detection coverage percentage
- ✅ Data volume analysis

---

## File Requirements

### ⚠️ FRESH DATA CRITICAL

**All four files MUST be freshly exported TODAY for THIS customer.**

Never use files from previous months or other customers.

---

## The 4 Files You Need

| # | File Name | Required? | What It Is | Where It Comes From |
|---|-----------|-----------|-----------|-------------------|
| 1 | `rules.json` | ✅ YES | Your detection rules | Rules management system |
| 2 | `detection_results.csv` | ✅ YES | Rules that are triggering | SecOps Dashboard |
| 3 | `event_results.csv` | ✅ YES | Events in your environment | SecOps Queries |
| 4 | `log_volume.csv` | ⭐ OPT | Log volume data | SecOps Queries |

### Export Timing

```
All files MUST:
  ✅ Be exported TODAY (or yesterday at latest)
  ✅ Be from SAME date/time period
  ✅ Be for THIS customer ONLY
  ✅ Be fresh, not from archive
  ✅ Not be older than 1 week
```

---

## Step 1: Download JSON Rules File

### What It Is

`rules.json` is a JSON-formatted export of ALL your detection rules.

Contains:
- Rule names and IDs
- Enabled/disabled status
- Severity levels
- Rule descriptions
- Rule logic and conditions
- Author information
- Creation/modification dates

### How to Download

1. **Log into your rules management system or Google SecOps**

2. **Navigate to the Rules section**
   - In SecOps: Security Operations → Rules
   - In your rules system: Admin → Rules Export

3. **Find the Export option**
   - Look for: Export, Download, or Backup button

4. **Select JSON format**
   - Choose: JSON or .json format
   - NOT XML, CSV, or other formats

5. **Download the file**
   - File will be named something like:
     - `rules.json`
     - `rules_export.json`
     - `detection_rules.json`
   - Rename if needed to: `rules.json`

6. **Save to Downloads folder**
   - Keep in same location as other files

### Verification

```
☐ File exists: rules.json
☐ Size is reasonable (100 KB - 10 MB)
☐ Exported TODAY or YESTERDAY
☐ Contains JSON data (not text or HTML)
☐ Not corrupted (can open in text editor)
```

### File Format

```json
{
  "rules": [
    {
      "name": "Brute_Force_Detection",
      "ruleId": "abc123",
      "severity": "HIGH",
      "enabled": true,
      "description": "Detects brute force attacks"
    },
    {
      "name": "Office365_Suspicious",
      "ruleId": "xyz789",
      "severity": "MEDIUM",
      "enabled": true,
      "description": "Detects suspicious Office 365 activity"
    }
    ... more rules ...
  ]
}
```

---

## Step 2: Download Detection Results CSV

### What It Is

`detection_results.csv` contains data about rules that are actively triggering/detecting events.

Shows:
- Rules that have generated detections
- Detection counts
- Rule metadata
- Trigger information

### How to Download

1. **Log into Google SecOps Dashboard**

2. **Create or access a dashboard**
   - Navigation: Dashboards → New or Existing

3. **Add a new table for detection rules query**
   - Click: + Add Table

4. **Copy and paste this query:**

```

// REVISED - Aggregates per RULE, includes array of distinct event_type only
// Groups by rule_id for uniqueness; collects distinct underlying UDM event types per rule
// Removed arrays for log_type and product_event per request
// Assumes ~1.5 KB per detection for GB estimate; adjust based on actual query span
// Optional: Uncomment time/event filters for performance and relevance
detection.detection.rule_name != ""  // Full UDM: security_result.detection.rule_name != "" (uncommented for active filtering)
// Variables for rule details
// $rule_id = detection.detection.rule_id  // Full UDM: security_result.detection.rule_id
$rule_name = detection.detection.rule_name  // Full UDM: security_result.detection.rule_name
$rule_description = detection.detection.description  // Full UDM: security_result.detection.description
$rule_state = detection.detection.alert_state  // Full UDM: security_result.detection.alert_state
$rule_severity = detection.detection.severity  // Full UDM: security_result.detection.severity
$rule_type = detection.detection.rule_type  // Full UDM: security_result.detection.type
// Variable for underlying event metadata (retained for event_type array)
$log_type = detection.collection_elements.references.event.metadata.log_type
$event_type = detection.collection_elements.references.event.metadata.event_type
$product_event = detection.collection_elements.references.event.metadata.product_event_type
not $rule_name = /(STAGE_|DEV_|_PR_)/  // For case-insensitivity in 2.0: re.regex($rule_name, "(?i)stage_|dev_|_pr_")
// Match only on rule_id to aggregate all detections per rule (recommended for unique groups)
// Alternative: match: $rule_name  (if you prefer grouping by name)
match:
  $rule_name, $rule_description, $rule_severity, $rule_state, $rule_type, $log_type, $product_event
outcome:
  $event_type_arr = array_distinct($event_type)  // Retained: distinct UDM event types per rule
order:
  $rule_state desc
limit:
  1000
  
```

5. **Click Run button**
   - Wait for query to execute (1-3 minutes)
   - Results display in table

6. **Export as CSV**
   - Click: ⋮ (three dots menu)
   - Select: Export → Download as CSV
   - File downloads as `results.csv`

7. **Rename to `detection_results.csv`**
   - Rename the downloaded file
   - Save in Downloads folder

### Expected Columns

Your CSV should have headers like:
- `rule_name`
- `rule_description`
- `rule_severity`
- `rule_state` or `alert_state`
- `rule_type`
- Detection count columns
- `count` (detection count)

### Verification

```
☐ File exists: detection_results.csv
☐ Exported TODAY or YESTERDAY
☐ Has header row (first line)
☐ Multiple data rows (not empty)
☐ Opens in Excel/text editor
☐ File size is reasonable (100 KB - 10 MB)
```

---

## Step 3: Download Event Results CSV

### What It Is

`event_results.csv` contains all events occurring in your environment.

Shows:
- Log types (Windows, Office 365, etc.)
- Event types (login, process, file access, etc.)
- Product event types (specific event IDs)
- Event counts

### How to Download

1. **Log into Google SecOps native query interface**

2. **Create a new native query**
   - Go to: Queries → New Query
   - Select: Native Query (not dashboard)

3. **Copy and paste this query:**

```

metadata.log_type != ""
 principal.hostname != ""
 metadata.event_type != "EVENTTYPE_UNSPECIFIED"
 metadata.product_event_type != ""

 $host = principal.hostname
 $log_type = metadata.log_type
 $event_type = metadata.event_type
 $product_event_type = metadata.product_event_type
$day = timestamp.get_date(metadata.event_timestamp.seconds, "UTC")
match:
  $log_type, $event_type, $product_event_type, $day
outcome:
  $event_count = count(metadata.id)
//  $host_list = array_distinct($host)
order:
  $event_count desc
limit:
  10000

```

4. **Click Run button**
   - Wait for query to execute (1-5 minutes)
   - Results display

5. **Export as CSV**
   - Click: Export or Download
   - Choose: CSV format
   - File downloads as `results.csv`

6. **Rename to `event_results.csv`**
   - Rename the downloaded file
   - Save in Downloads folder

### Expected Columns

Your CSV should have:
- `log_type` - Type of log (WINDOWS, OFFICE365, etc.)
- `event_type` - Type of event (authentication, process, file, etc.)
- `product_event_type` - Product-specific event ID
- `count` - Number of events

### Verification

```
☐ File exists: event_results.csv
☐ Exported TODAY or YESTERDAY
☐ Has header row (first line)
☐ Multiple data rows (not empty)
☐ Contains event combinations
☐ File size is reasonable (50 KB - 5 MB)
```

---

## Step 4: Download Log Volume CSV (Optional)

### What It Is

`log_volume.csv` contains data about log volumes per week.

Shows:
- Log type volumes
- Events per week
- Gigabytes per week
- Date ranges

### Why Optional

- Adds context to analysis
- Shows which log types are highest volume
- Helps prioritize detection efforts
- Script works fine without it

### How to Download

1. **Log into Google SecOps**

2. **Create a new query for log volumes**
   - Go to: Queries → New Query

3. **Copy and paste this query:**

```
/*Each week date represents the start of that ISO week (Monday). So 2026-01-11 contains all events from Jan 11-17, 2026.
The $week_array = array_distinct($week) line would just show the unique week per row (since you're already grouping by week).
*/
metadata.log_type != ""
 $log_type = metadata.log_type
 $week = timestamp.get_timestamp(metadata.event_timestamp.seconds, "WEEK", "UTC")
match:
  $log_type, $week
outcome:
  $event_count = count(metadata.id)
  $week_gigabytes = ($event_count * 1024) / (1024 * 1024 * 1024)
  $week_array = array_distinct($week)
order:
  $log_type asc, $week desc
limit:
  10000

```

4. **Click Run button**
   - Wait for query to execute

5. **Export as CSV**
   - Click: Export or Download
   - Choose: CSV format
   - File downloads

6. **Rename to `log_volume.csv`**
   - Save in Downloads folder

### Expected Columns

- `log_type`
- `event_count`
- `volume_estimate` or similar
- Date range information

### Verification

```
☐ File exists: log_volume.csv (or skip - optional)
☐ Exported TODAY or YESTERDAY (if included)
☐ Has header row
☐ Multiple data rows
☐ Contains volume information
```

---

## Step 5: Verify Your Files

### Pre-Analysis Checklist

Before running the script, verify all files:

#### Files Exist

```
☐ rules.json exists
☐ detection_results.csv exists
☐ event_results.csv exists
☐ log_volume.csv exists (or will skip - optional)
```

#### File Names Exact

File names are **CASE-SENSITIVE** on macOS/Linux:

```
✅ Correct:
rules.json
detection_results.csv
event_results.csv
log_volume.csv

❌ Wrong:
Rules.json
Rules.JSON
RULES.JSON
detection-results.csv
detection_results.CSV
events.csv
```

#### Files Are Fresh

```
☐ All files exported TODAY (or YESTERDAY at latest)
☐ All files from SAME date
☐ NOT older than 1 week
☐ NOT from previous months
☐ NOT from archive storage
```

#### Customer Specific

```
☐ Files are for THIS customer
☐ NOT reused from previous analysis
☐ NOT mixed from different customers
☐ NOT shared with other projects
```

#### File Sizes Reasonable

```
rules.json: 
  ☐ 100 KB - 10 MB

detection_results.csv:
  ☐ 50 KB - 10 MB

event_results.csv:
  ☐ 50 KB - 5 MB

log_volume.csv:
  ☐ 10 KB - 500 KB (if included)
```

#### Can Open Files

```
☐ rules.json opens in text editor (valid JSON)
☐ detection_results.csv opens in Excel
☐ event_results.csv opens in Excel
☐ log_volume.csv opens in Excel (if included)
```

---

## Step 6: Run the Python Script

### Script Location

```
customer_audit_v10.py
```

This is the ACTUAL script name (not `compare_unmapped_events.py`).

### Running on Windows

**Option 1: Command Prompt**
```bash
cd Downloads
python customer_audit_v10.py
```

**Option 2: Double-click**
1. Open Downloads folder
2. Find `customer_audit_v10.py`
3. Double-click to run

### Running on macOS/Linux

**Terminal:**
```bash
cd ~/Downloads
python3 customer_audit_v10.py
```

**Or make executable:**
```bash
chmod +x customer_audit_v10.py
./customer_audit_v10.py
```

### What Happens

Script will open file dialogs asking for:

1. **JSON Rules File**
   - Click: Open
   - Select: rules.json
   - Click: Open

2. **Detection Results CSV**
   - Click: Open
   - Select: detection_results.csv
   - Click: Open

3. **Event Results CSV**
   - Click: Open
   - Select: event_results.csv
   - Click: Open

4. **Log Volume CSV (Optional)**
   - Click: Open
   - Select: log_volume.csv
   - OR: Click Cancel to skip

### Console Output

```
================================================================================
  SecOps Rule Comparison Tool
  Compare JSON Rule Export vs Detection/Event CSV Data
================================================================================

Step 1: Select your JSON rules file
[Dialog opens - you select rules.json]
✓ Selected: rules.json

Step 2: Select detection_results.csv
[Dialog opens - you select detection_results.csv]
✓ Selected: detection_results.csv

Step 3: Select event_results.csv
[Dialog opens - you select event_results.csv]
✓ Selected: event_results.csv

Step 4: Select log_volume.csv (optional)
[Dialog opens - you select log_volume.csv or cancel]
✓ Selected: log_volume.csv

Loading files...
  ✓ JSON parsed successfully
  ✓ Extracted 342 rules
  ✓ Loaded detection results
  ✓ Loaded event results
  ✓ Loaded log volume data

Analyzing data...

📊 Analysis Summary:
   Total rules in JSON: 342
   Enabled rules: 325
   Rules triggering: 245
   Enabled but not triggering: 80
   Event coverage: 57.6%
   Unmapped events: 70

Generating HTML report...

✓ Report saved to: /Users/yourname/Downloads/rule_comparison_report.html
✓ Report opened in browser

================================================================================
Done!
================================================================================
```

---

## Step 7: Review the HTML Report

### Report File Location

```
~/Downloads/rule_comparison_report.html
```

### Auto-Open

Report opens automatically in your default browser.

### Manual Open

If it doesn't open:
1. Open Downloads folder
2. Find: `rule_comparison_report.html`
3. Double-click to open in browser

### Report Sections

1. **Header**
   - Tool name
   - Generation timestamp
   - Summary statistics

2. **Summary Cards**
   - Total Rules
   - Enabled Rules
   - Rules Triggering
   - Event Coverage %
   - Unmapped Events

3. **Rules by State**
   - ENABLED vs DISABLED breakdown
   - Percentages

4. **Rules by Severity**
   - CRITICAL, HIGH, MEDIUM, LOW breakdown
   - Distribution chart

5. **Rules Not Triggering**
   - List of enabled rules with no activity
   - Potential problems

6. **Top Log Types by Volume**
   - Data volume analysis
   - Which log types are highest volume

7. **Unmapped Events**
   - Events with no detection rule
   - Security gaps

---

## Step 8: Interpret Your Results

### Summary Statistics

**Total Rules:** How many rules exist in your system
- Example: 342 total rules

**Enabled Rules:** How many are actively monitoring
- Example: 325 enabled (95%)

**Rules Triggering:** How many are generating detections
- Example: 245 actively triggering (72%)

**Event Coverage:** What percentage of events are detected
- Example: 57.6% coverage

**Unmapped Events:** What events have NO detection
- Example: 70 unmapped events (gaps)

### Analysis Results

#### Healthy Indicators ✅

```
Rules Triggering: 90%+ of enabled rules
Event Coverage: 80%+ of events detected
Rules by Severity: Good distribution (not all LOW)
Active Rules: Majority actively detecting
```

#### Warning Indicators ⚠️

```
Rules Triggering: <50% of enabled rules
Event Coverage: <50% of events detected
Rules Not Triggering: Many dormant rules
High-Risk Unmapped: CRITICAL/HIGH events undetected
```

### Common Findings

**Finding: Many rules enabled but not triggering**
- Cause: Rules may be misconfigured
- Action: Review rule thresholds and conditions
- Fix: Adjust rule logic or enable dormant rules

**Finding: High coverage but still unmapped events**
- Cause: Normal - not all events need detection
- Action: Review unmapped events for risk
- Fix: Create rules for high-risk events

**Finding: Low overall coverage**
- Cause: Gaps in detection capability
- Action: Prioritize rule creation
- Fix: Build rules for critical threats

---

## Troubleshooting

### Script Won't Run

**Error: "Python not found"**
```bash
# Check if Python is installed
python --version
# or
python3 --version

# Install if needed (different for Windows/Mac/Linux)
```

**Error: "tkinter not found"**
```bash
# Windows:
python -m pip install --upgrade tk

# macOS:
brew install python-tk@3.9

# Linux:
sudo apt-get install python3-tk
```

---

### File Selection Issues

**"No JSON file selected. Exiting."**
- Solution: You clicked Cancel on the JSON dialog
- Fix: Run script again, make sure to select rules.json

**"No detection CSV selected. Exiting."**
- Solution: You clicked Cancel on detection CSV dialog
- Fix: Run script again, select detection_results.csv

---

### File Content Issues

**"Failed to load JSON rules"**
- Check: Is rules.json a valid JSON file?
- Fix: Open in text editor, verify JSON structure
- Action: Re-export rules from your system

**"Failed to load CSV"**
- Check: Is CSV file valid?
- Check: Does it have header row?
- Fix: Re-export from SecOps

---

### Data Freshness Issues

**"My results look different than last month"**

This is NORMAL! Rules and events change daily:
- New rules created
- Rules enabled/disabled
- New event types appear
- Detections change

To track changes, run analysis monthly with fresh data each time.

---

### Multi-Customer Issues

**"Results for Customer B look like Customer A"**

Solution: You used Customer A's files for Customer B!

Fix:
1. Export FRESH rules.json for Customer B (TODAY)
2. Export FRESH detection_results.csv for Customer B (TODAY)
3. Export FRESH event_results.csv for Customer B (TODAY)
4. Re-run analysis

Each customer needs DIFFERENT files!

---

## Quick Reference

### File Checklist

```
Before running script:

☐ rules.json (TODAY)
☐ detection_results.csv (TODAY)
☐ event_results.csv (TODAY)
☐ log_volume.csv (TODAY, optional)

All files:
☐ Named exactly as shown
☐ Exported today or yesterday
☐ From SAME date/time
☐ From THIS customer only
☐ Not reused from previous months
```

### Script Command

```bash
# Windows
python customer_audit_v4.py

# macOS/Linux
python3 customer_audit_v4.py
```

### Output File

```
~/Downloads/rule_comparison_report.html
```

---

## Next Steps

1. ✅ Export fresh rules.json TODAY (THIS customer)
2. ✅ Export fresh detection_results.csv TODAY (THIS customer)
3. ✅ Export fresh event_results.csv TODAY (THIS customer)
4. ✅ Export fresh log_volume.csv TODAY (optional)
5. ✅ Verify all files are fresh and correct
6. ✅ Run: `python3 customer_audit_v4.py`
7. ✅ Review: rule_comparison_report.html
8. ✅ Plan improvements based on findings
9. ✅ Schedule monthly re-runs for trending

---

## Key Takeaways

✅ **FRESH DATA EVERY TIME** - Never reuse old files  
✅ **FOR EACH CUSTOMER** - Never mix customer data  
✅ **ALL 4 FILES TOGETHER** - Same date/time period  
✅ **SCRIPT NAME** - customer_audit_v4.py  
✅ **OUTPUT FILE** - rule_comparison_report.html  

---

## Additional Resources

- **HOW_TO_USE_SCRIPT.md** - Script usage details
- **DOWNLOAD_AND_PREPARE_FILES.md** - Detailed export instructions
- **WHAT_IS_RULES_JSON.md** - Understanding rules.json
- **CRITICAL_REQUIREMENT_FRESH_DATA.md** - Why fresh data matters
- **DETECTION_COVERAGE_ANALYSIS_GUIDE.md** - Deep dive analysis

---

**Ready? Start by exporting your fresh data TODAY!** 🚀
