# YARAL Event Mapping Analysis Tool - Complete Step-by-Step Guide

## 📋 Table of Contents

1. [What This Tool Does](#what-this-tool-does)
2. [File Requirements](#file-requirements)
3. [Step 1: Download Customer Rules from host where rules are managed](#step-1-download-customer-rules-from-host-where-rules-are-managed)
4. [Step 2: Download Detection Results CSV](#step-2-download-detection-results-csv)
5. [Step 3: Download Event Results CSV](#step-3-download-event-results-csv)
6. [Step 4: Download Log Volume CSV (Optional)](#step-4-download-log-volume-csv-optional)
7. [Step 5: Verify Your Files](#step-5-verify-your-files)
8. [Step 6: Run the Python Script](#step-6-run-the-python-script)
9. [Step 7: Review the HTML Report](#step-7-review-the-html-report)
10. [Step 8: Download as PDF](#step-8-download-as-pdf)
11. [Troubleshooting](#troubleshooting)

---

## What This Tool Does

### 🎯 Purpose

The **YARAL Event Mapping Comparison Tool** analyzes your detection rules and identifies which events in your environment are being detected and which ones are NOT detected.

### 📊 Main Function

```
Detection Rules (from SecOps)
           |
           v
    +-----------+
    |  COMPARE  |  ← Script compares these two
    +-----------+
           ^
           |
All Events (from SecOps)

Result:
✓ Mapped Events = Events being detected by rules
✗ Unmapped Events = Events NOT being detected (gaps in coverage)
```

### 📈 What You Get

**HTML Report showing:**
1. ✓ Count of active detection rules
2. ✓ Count of mapped events (detected)
3. ✓ Count of unmapped events (NOT detected)
4. ✓ Overall detection coverage percentage
5. ✓ Table of all detection rules
6. ✓ Top log types by volume
7. ✓ List of unmapped event combinations (gaps to fill)
8. ✓ PDF download option

---

## File Requirements

The script requires **3 CSV files** from Google SecOps:

| # | File Name | From Which Query | Required? | What It Contains |
|---|-----------|------------------|-----------|-----------------|
| 1 | `detection_results.csv` | Step 2 Query | ✅ YES | All your active detection rules |
| 2 | `event_results.csv` | Step 3 Query | ✅ YES | All events occurring in your environment |
| 3 | `log_volume.csv` | Step 1 Query | ⭐ OPTIONAL | Weekly event volume by log type |

**Key Point:** Files MUST be named exactly as shown above (case-sensitive on Linux/Mac)

---
## Step 1: Download Detection Results CSV

## Purpose
Download Customer Rules from the TAM instance.

## How to Download from host where rules are managed

### 1. Log into host with rules instance

## Step 2: Download Detection Results CSV

### Purpose
This file contains all your **active detection rules** that are monitoring your environment.

### What It Looks Like
```
Rulename | Logtype | Eventtype | Productevent | Day | event_count | trigger_count | estimated_gb_per_day
---------|---------|-----------|--------------|-----|-------------|---------------|-------------------
Rule_1   | FORTINET_FIREWALL | NETWORK_CONNECTION | traffic-forward | 2026-01-15 | 1245 | 13 | 0.025
Rule_2   | FORTINET_FIREWALL | NETWORK_CONNECTION | traffic-forward | 2026-01-14 | 1158 | 11 | 0.023
...
```

### How to Download from Google SecOps

#### 1. Log into Google SecOps Dashboard

- Follow the steps to create a new dashboard - https://docs.cloud.google.com/chronicle/docs/reports/native-dashboards
- Follow these steps to create a chart on the dashboard - https://docs.cloud.google.com/chronicle/docs/reports/manage-native-dashboard-charts
  - Use a table https://docs.cloud.google.com/chronicle/docs/reports/manage-native-dashboard-charts#view_a_chart_as_a_table

#### 2. Copy & Paste This Query

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

#### 3. Export as CSV

1. Results will display in a table
2. Click the **⋮ (three dots)** menu in top right
3. Select **Export** → **Download Instant Report**
4. File downloads (usually named `results.csv`)

#### 4. Rename the File

1. Find the downloaded file (usually in Downloads folder)
2. **Rename to:** `detection_results.csv`
   - Right-click → Rename (Windows)
   - Right-click → Get Info → Change name (Mac)
   - Use `mv` command (Linux)

#### ✅ Verification

Open the file in Excel or text editor and verify:
- First row contains headers
- Has columns: `Rulename`, `Logtype`, `Eventtype`, `Productevent`, `trigger_count`, `estimated_gb_per_day`
- Contains multiple rows of detection rules
- No corruption or encoding issues

---

## Step 3: Download Event Results CSV

### Purpose
This file contains **all events** that occurred in your environment during the analysis period.

### What It Looks Like
```
log_type | event_type | product_event_type | day | event_count | host_list
---------|----------|-------------------|-----|-------------|----------
FORTINET_FIREWALL | NETWORK_CONNECTION | traffic-forward | 2026-01-15 | 1245 | [host1, host2, ...]
OFFICE_365 | USER_LOGIN | UserLoginFailed | 2026-01-15 | 45 | [office_user1, ...]
...
```

### How to Download from Google SecOps

#### 1. Create a New Query

Go to: **Google SecOps Console** → **Investigation** → **Search**

#### 2. Copy & Paste This Query

```
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

#### 3. Run the Query

Click **Run Search** button

⏳ Wait for results (30 seconds to 2 minutes)

#### 4. Export as CSV

1. Results will display in a table
2. Click the **Download Arrow** menu
3. Select **Download as CSV**
4. File downloads

#### 5. Rename the File

**Rename to:** `event_results.csv`

#### ✅ Verification

Open the file and verify:
- First row contains headers
- Has columns: `log_type`, `event_type`, `product_event_type`, `event_count`, `host_list`
- Contains multiple rows of events (usually 100-500+)
- No errors or corruption

---

## Step 4: Download Log Volume CSV (Optional)

### Purpose
This file shows **how much data** each log type generated per week and the **time period** of your analysis.

### What It Looks Like
```
log_type | week | event_count | week_gigabytes | week_array
---------|------|-------------|----------------|----------
FORTINET_FIREWALL | 2026-01-11 | 95432 | 2.45 | [2026-01-11]
OFFICE_365 | 2026-01-11 | 12450 | 0.32 | [2026-01-11]
FORTINET_FIREWALL | 2026-01-18 | 87650 | 2.23 | [2026-01-18]
...
```

### How to Download from Google SecOps

#### 1. Create a New Query

Go to: **Google SecOps Console** → **Investigation** → **Search**

#### 2. Copy & Paste This Query

```
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

#### 3. Run the Query

Click **Run** button

⏳ Wait for results

#### 4. Export as CSV

1. Results will display in a table
2. Click the **Download Arrow** menu
3. Select **Download as CSV**
4. File downloads

#### 5. Rename the File

**Rename to:** `log_volume.csv`

#### ✅ Verification

Open the file and verify:
- First row contains headers
- Has columns: `log_type`, `week`, `event_count`, `week_gigabytes`, `week_array`
- Dates in `week` column are format: YYYY-MM-DD (e.g., 2026-01-11)
- Contains multiple weeks of data (at least 2-4 weeks recommended)
- Shows realistic volume numbers

---

## Step 5: Verify Your Files

### File Location

All three files should be in: **Downloads folder** (`C:\Users\YourName\Downloads` or `~/Downloads`)

### Check File Names

```
✅ CORRECT                    ❌ INCORRECT
detection_results.csv         Detection Results.csv (space)
event_results.csv             event_result.csv (missing 's')
log_volume.csv                log_volumes.csv (extra 's')
```

### Check File Sizes

Expected minimum sizes:
- `detection_results.csv` → At least 2 KB
- `event_results.csv` → At least 3 KB
- `log_volume.csv` → At least 1 KB

### Check File Format

Open each file in Excel or text editor and verify:
- No corruption (text is readable)
- First row contains column headers
- Data rows follow the headers
- No error messages

### Folder Structure Example

```
Downloads/
├── detection_results.csv      ← From Step 1 query
├── event_results.csv          ← From Step 2 query
├── log_volume.csv             ← From Step 3 query (optional)
└── compare_unmapped_events.py ← Python script
```

---

## Step 6: Run the Python Script

### On Windows

#### 1. Open Command Prompt

Press: `Windows Key + R`  
Type: `cmd`  
Press: `Enter`

#### 2. Navigate to Downloads

```batch
cd Downloads
```

#### 3. Run the Script

```batch
python compare_unmapped_events.py
```

### On macOS

#### 1. Open Terminal

Applications → Utilities → Terminal (or Cmd+Space, type "Terminal")

#### 2. Navigate to Downloads

```bash
cd ~/Downloads
```

#### 3. Run the Script

```bash
python3 compare_unmapped_events.py
```

### On Linux

#### 1. Open Terminal

Ctrl+Alt+T (or open Terminal application)

#### 2. Navigate to Downloads

```bash
cd ~/Downloads
```

#### 3. Run the Script

```bash
python3 compare_unmapped_events.py
```

---

## Step 7: File Selection Dialogs

When you run the script, it will ask for files one at a time.

### Dialog 1: Detection Results CSV

```
Title: "Select Detection Results CSV"

Action:
1. Look for "detection_results.csv" in the list
2. Click on it to select it
3. Click "Open" button
```

**Console Output:**
```
✓ Selected: detection_results.csv

Loading detection rules...
  Column names found: ['Rulename', 'Logtype', 'Eventtype', 'Productevent', ...]
  Processed 100 rows
✓ Loaded 100 detection rules
```

### Dialog 2: Event Results CSV

```
Title: "Select Event Results CSV"

Action:
1. Look for "event_results.csv"
2. Click to select
3. Click "Open"
```

**Console Output:**
```
✓ Selected: event_results.csv

Loading event results...
  Column names found: ['log_type', 'event_type', 'product_event_type', ...]
  Processed 165 rows
✓ Loaded 165 unique combinations
```

### Dialog 3: Log Volume CSV (Optional)

```
Title: "Select Log Volume CSV (optional)"

Action (choose one):
Option A: Select "log_volume.csv" and click "Open"
Option B: Click "Cancel" to skip (file is optional)
```

**Console Output (if you select it):**
```
✓ Selected: log_volume.csv

Loading log volume data...
  Column names found: ['log_type', 'week', 'event_count', 'week_gigabytes', ...]
  Processed 39 rows
✓ Loaded 39 log volume records
```

**Console Output (if you skip it):**
```
⊘ Skipped log volume file (optional)
```

---

## Step 8: Script Processing

### What the Script Does

```
Processing files...

1. Load Detection Rules
   ✓ Reads all 100 detection rules
   ✓ Extracts: rule name, log type, event type, product event

2. Load Event Results
   ✓ Reads all 165 events
   ✓ Extracts: log type, event type, product event

3. Load Log Volume (if provided)
   ✓ Reads volume data
   ✓ Calculates date range

4. Compare
   ✓ Checks which events are detected by rules
   ✓ Identifies unmapped events (gaps)
   ✓ Calculates coverage percentage

5. Generate Report
   ✓ Creates HTML with tables and charts
   ✓ Saves to Downloads folder
   ✓ Opens in browser
```

### Expected Console Output

```
================================================================================
SUMMARY STATISTICS
================================================================================
Detection rules loaded: 100
Total unique event combinations: 165
Mapped to rules: 95
NOT mapped to rules: 70
Coverage: 57.6%
Data period: Jan 11 - Feb 22, 2026 (6 weeks)
================================================================================

Generating HTML report...

✓ HTML report saved to:
  C:\Users\YourName\Downloads\unmapped_events_report.html

✓ Report generated successfully!
✓ Opening report in default browser...

💡 TIP: Click '📥 Download as PDF' button to save report as PDF
💡 TIP: Scroll horizontally to see all table columns

================================================================================
Done! The HTML report has been opened in your browser.
================================================================================
```

---

## Step 9: Review the HTML Report

### Browser Opens Automatically

Your default web browser will open showing the report.

### Report Sections (Top to Bottom)

#### 1. Header
```
📊 YARAL Event Mapping Analysis Report
Detection Coverage Analysis - Granular Rule Mappings

Generated on January 15, 2026 at 2:30pm
📅 Data Period: Jan 11 - Feb 22, 2026 (6 weeks)

[📥 Download as PDF] ← Click to save as PDF
```

#### 2. Summary Cards (4 boxes)
```
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  Active Rules    │ │ Mapped Events    │ │Unmapped Events   │ │Detection Coverage│
│      100         │ │      95          │ │      70          │ │     57.6%        │
└──────────────────┘ └──────────────────┘ └──────────────────┘ └──────────────────┘
```

#### 3. Coverage Overview
```
Coverage Overview
[████████░░░░░░░░░░░░░░░░░░░░] 57.6% Covered
```

#### 4. Detection Rules Coverage Table

```
RULE NAME | LOG TYPE | EVENT TYPE | PRODUCT EVENT | TRIGGERS | EST. GB/DAY
----------|----------|----------|---|---|---
Rule_1 | FORTINET_FIREWALL | NETWORK_CONNECTION | traffic-forward | 13 | 0.025
Rule_2 | FORTINET_FIREWALL | NETWORK_CONNECTION | traffic-forward | 11 | 0.023
...
```

**✨ Special Feature:** Scroll left and right to see all columns

#### 5. Top Log Types by Volume (if log_volume.csv provided)

```
📊 Top Log Types by Volume
📅 Data Period: Jan 11 - Feb 22, 2026 (6 weeks)

LOG TYPE | WEEKLY EVENTS | WEEKLY VOLUME (GB) | VOLUME COMPARISON
---------|---------------|-------------------|------------------
FORTINET_FIREWALL | 95,432 | 2.45 | [████████████] 100%
OFFICE_365 | 12,450 | 0.32 | [███░░░░░░░░] 13%
...
```

#### 6. Unmapped Event Combinations

```
FORTINET_FIREWALL (28 unmapped events)

EVENT TYPE | PRODUCT EVENT TYPE | STATUS
-----------|-------------------|--------
NETWORK_CONNECTION | unknown_event_type_1 | Unmapped
NETWORK_CONNECTION | unknown_event_type_2 | Unmapped
...
```

---

## Step 9: Download as PDF

### Click the PDF Button

In the report header, click the red button: **"📥 Download as PDF"**

### Select "Save as PDF"

Your browser's print dialog will open.

**Chrome/Edge:**
1. Find "Printer" dropdown
2. Select "Save as PDF"
3. Click "Save" button
4. Choose where to save
5. File is saved as PDF

**Firefox:**
1. Look for "Print to File" option
2. Select "PDF" format
3. Click "Save"

**Safari:**
1. Click "PDF" dropdown (bottom left)
2. Select "Save as PDF"
3. Choose location

### File is Saved

The PDF will be saved to your Downloads folder with all:
- ✓ Summary statistics
- ✓ Detection rules table
- ✓ Coverage charts
- ✓ Volume analysis
- ✓ Unmapped events
- ✓ Professional formatting
- ✓ Full color output

---

## Troubleshooting

### "No detection file selected. Exiting."

**Problem:** You clicked Cancel on the file dialog

**Solution:** Run the script again and select the file properly

---

### "Failed to load files. Exiting."

**Problem:** CSV files weren't loaded (0 rules loaded)

**Possible Causes:**
1. File names are wrong (case-sensitive)
2. File is in wrong location
3. File is corrupted or empty
4. File is open in Excel (blocking access)

**Solutions:**
1. Check file names match exactly:
   - `detection_results.csv`
   - `event_results.csv`
   - `log_volume.csv`
2. Verify files are in Downloads folder
3. Close any Excel windows with these files
4. Re-download the files from SecOps
5. Try again

---

### "Column names found: [...] but loaded 0 rules"

**Problem:** CSV has data but script didn't recognize it

**Cause:** Column names don't match expected values

**Solution:** The script is flexible and auto-detects column names. Try:
1. Make sure the CSV has data rows (not just headers)
2. Verify column names match what the query produces
3. Check for extra spaces in column names
4. Re-export from SecOps

---

### PDF download doesn't work

**Problem:** Clicking the PDF button does nothing

**Solutions:**
1. Try using keyboard shortcut: **Ctrl+P** (Windows) or **Cmd+P** (Mac)
2. Try a different browser
3. Check if pop-ups are blocked in browser
4. Try printing to a PDF printer instead

---

### Tables are cut off or too narrow

**Problem:** Can't see all table columns

**Solution:** 
1. Scroll left and right in the report (scroll bars at bottom of tables)
2. Make browser window wider
3. Zoom out the page: Ctrl+Minus (Windows) or Cmd+Minus (Mac)
4. In PDF: tables will expand to fit page width

---

### Script takes too long to run

**Normal Times:**
- Loading files: 5-10 seconds
- Processing: 5-10 seconds
- Total: 10-20 seconds

**If it takes longer:**
1. You might have very large CSV files (100,000+ rows)
2. Your computer is busy with other tasks
3. Try closing other programs

---

### Browser doesn't open automatically

**Problem:** Script finished but no browser window opened

**Solution:**
1. Check your Downloads folder for `unmapped_events_report.html`
2. Open it manually in your browser
3. Or run this command in terminal:
   - Windows: `start unmapped_events_report.html`
   - Mac: `open unmapped_events_report.html`
   - Linux: `xdg-open unmapped_events_report.html`

---

## Quick Reference: File Names

### Must Use These Exact Names

```
FROM QUERY:                    RENAME TO:
Step 1 (Log Volume)      →     log_volume.csv
Step 2 (Detection)       →     detection_results.csv
Step 3 (Events)          →     event_results.csv
```

### Case Sensitivity Matters

These will NOT work:
- ❌ Detection_Results.csv (capital D)
- ❌ detection-results.csv (dash instead of underscore)
- ❌ detectionresults.csv (no underscores)
- ❌ DETECTION_RESULTS.CSV (all caps on Linux/Mac)

---

## Summary: Complete Workflow

```
1. LOGIN to Google SecOps
2. RUN Step 1 Query → Download → Rename to log_volume.csv
3. RUN Step 2 Query → Download → Rename to detection_results.csv
4. RUN Step 3 Query → Download → Rename to event_results.csv
5. PLACE all files in Downloads folder
6. OPEN terminal/command prompt
7. RUN: python compare_unmapped_events.py
8. SELECT files when prompted
9. VIEW HTML report in browser
10. CLICK "📥 Download as PDF" to save

DONE! 🎉
```

---

## Next Steps

After reviewing the report:

1. **Understand the gaps** - Which event combinations are NOT detected?
2. **Prioritize** - Focus on high-volume unmapped events first
3. **Create rules** - Build detection rules for critical unmapped events
4. **Test** - Verify new rules trigger correctly
5. **Re-run** - Run this analysis again to verify improvement

See **DETECTION_COVERAGE_ANALYSIS_GUIDE.md** for detailed analysis methodology.

---

**Version:** 1.0  
**Script Version:** 2.3 (Scrollable)  
**Last Updated:** January 15, 2026
