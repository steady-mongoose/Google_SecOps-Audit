# Google SecOps File Download & Preparation Guide

Complete step-by-step instructions for downloading detection data from Google SecOps and preparing files for the Python analysis script.

---

## Overview

The Python script (`compare_unmapped_events.py`) requires **3 CSV files** from Google SecOps:

| File | Source Query | Required? | Purpose |
|------|--------------|-----------|---------|
| `detection_results.csv` | Step 2: Detection Rules | ✅ **Yes** | Lists all triggered detection rules |
| `event_results.csv` | Step 3: Raw Events | ✅ **Yes** | Lists all raw events in your environment |
| `log_volume.csv` | Step 1: Log Volume | ⭐ **Optional** | Shows top log types by volume & date range |

---

## ⚠️ Important Notes

**File Naming:**
- File names are **case-sensitive** on macOS/Linux
- Use **exact names** shown in this guide
- Store all files in your Downloads folder (or same location)
- Never rename files after downloading

**File Format:**
- Must be CSV (comma-separated values)
- UTF-8 encoding
- Must contain header row with column names
- Export from Dashboard queries (not native query interface for detection rules)

---

## 📥 File 1: detection_results.csv

### Step 1: Access Google SecOps Dashboard

1. Open Google SecOps web console
2. Navigate to **Dashboard** section (top navigation)
3. Click **Create new dashboard** OR select existing dashboard

### Step 2: Create Detection Rules Query

**In the Dashboard table:**

1. Click **+ Add Table** (or use existing table)
2. Copy and paste this query into the query editor:

```
detection.detection_rule_name != ""
$rule_name = detection.detection_rule_name
$rule_description = detection.detection_description
$rule_summary = detection.detection_summary
$rule_threat = detection.detection_threat_name
$rule_severity = detection.detection_severity
$rule_category = detection.detection_category
$rule_author = detection.detection_rule_author
$update_time = detection.detection_last_updated_time.seconds
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

### Step 3: Run & Export

1. Click **Run** button in dashboard
2. Wait for results to load (shows count of rules detected)
3. Results table will display with columns:
   - `detection_rule_name`
   - `mapped_log_type`
   - `mapped_event_type`
   - `mapped_product_event`
   - `alert_count`
   - `last_trigger_time`

### Step 4: Download as CSV

1. Click **⋮ (three dots)** menu in table header
2. Select **Export** > **Download as CSV**
3. File will download as `results.csv` or similar
4. **Rename it to:** `detection_results.csv`
5. **Move to:** Downloads folder

### ✅ Verification

Open `detection_results.csv` in Excel/text editor. Verify:
- First row contains headers
- Columns include: `rule_name`, `rule_description`, `rule_summary`, `rule_threat`, `rule_severity`, `rule_category`, `rule_author`, `alert_count`, `last_trigger_time`, `estimated_daily_gb`
- Multiple rows of detection rules listed
- No corruption or encoding issues

---

## 📥 File 2: event_results.csv

### Step 1: Access Google SecOps Native Query

1. In Google SecOps, go to **Query** section (top navigation)
2. Click **New Query** 
3. Select **Native Query** (not dashboard)

### Step 2: Create Raw Events Query

Copy and paste this query into the query editor:

```
metadata.log_type != ""
metadata.event_timestamp.seconds > 0
$log_type = metadata.log_type
$event_type = metadata.event_type
$product_event_type = metadata.product_event_type
match:
  $log_type, $event_type, $product_event_type
outcome:
  $event_count = count(metadata.id)
  $sample_host = array_distinct(metadata.hostname)[0]
order:
  $log_type asc, $event_type asc, $product_event_type asc
limit:
  10000
```

### Step 3: Run Query

1. Click **Run** button
2. Wait for results (may take 30 seconds to 2 minutes depending on volume)
3. Results will show unique combinations of:
   - `log_type`
   - `event_type`
   - `product_event_type`
   - `event_count` (how many of each combination)
   - `sample_host`

### Step 4: Download as CSV

1. Results displayed in query interface
2. Click **⋮ (three dots)** menu
3. Select **Export** > **Download as CSV** (or **Download**)
4. File will download as `results.csv` or `query_results.csv`
5. **Rename it to:** `event_results.csv`
6. **Move to:** Downloads folder

### ✅ Verification

Open `event_results.csv` in Excel/text editor. Verify:
- First row contains headers
- Columns include: `log_type`, `event_type`, `product_event_type`, `event_count`
- Multiple rows of events listed (typically 100-500+ combinations)
- File is readable and not corrupted

---

## 📥 File 3: log_volume.csv (OPTIONAL)

### Step 1: Access Google SecOps Native Query

1. In Google SecOps, go to **Query** section
2. Click **New Query** > **Native Query**

### Step 2: Create Log Volume Query

Copy and paste this query into the query editor:

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

**Note:** Each week date represents the start of that ISO week (Monday). So 2026-01-11 contains all events from Jan 11-17, 2026.

### Step 3: Run Query

1. Click **Run** button
2. Wait for results (may take 1-2 minutes)
3. Results will show for each week:
   - `log_type`
   - `week` (ISO week start date, format: YYYY-MM-DD)
   - `event_count`
   - `week_gigabytes`

### Step 4: Download as CSV

1. Results displayed in query interface
2. Click **⋮ (three dots)** menu
3. Select **Export** > **Download as CSV**
4. File will download as `results.csv` or similar
5. **Rename it to:** `log_volume.csv`
6. **Move to:** Downloads folder

### ✅ Verification

Open `log_volume.csv` in Excel/text editor. Verify:
- First row contains headers
- Columns include: `log_type`, `week`, `event_count`, `week_gigabytes`
- Multiple rows showing weekly data
- Dates in `week` column are formatted as YYYY-MM-DD (e.g., 2026-01-11)
- File shows data spanning multiple weeks (at least 2-4 weeks recommended)

---

## 📋 File Naming Quick Reference

**Critical:** Use these **exact names** when saving:

```
┌─────────────────────────────────────────┐
│ ✅ CORRECT NAMES                        │
├─────────────────────────────────────────┤
│ detection_results.csv                   │
│ event_results.csv                       │
│ log_volume.csv                          │
└─────────────────────────────────────────┘
```

**❌ INCORRECT names that will NOT work:**

```
❌ Detection Results.csv      (space)
❌ detection_result.csv       (missing 's')
❌ DETECTION_RESULTS.CSV      (all caps - may fail on Linux)
❌ Detection_Results.csv      (capital D)
❌ detection-results.csv      (dash instead of underscore)
❌ results.csv                (too generic)
❌ detections.csv             (wrong name)
```

---

## 🗂️ File Organization

### Recommended Folder Structure:

```
Downloads/
├── detection_results.csv      ← From Step 2 query
├── event_results.csv          ← From Step 3 query
├── log_volume.csv             ← From Step 1 query (optional)
└── compare_unmapped_events.py ← Python script
```

### Before Running Script:

1. ✅ All three files in Downloads folder
2. ✅ Correct file names (case-sensitive)
3. ✅ Files are readable (not locked by Excel)
4. ✅ Each file contains data (not empty)


### Detection Results Query Output

| Column Name | Source | What It Shows |
|-------------|--------|---------------|
| `rule_name` | Rule metadata | Name of the detection rule |
| `rule_description` | Rule metadata | Detailed description of what rule detects |
| `rule_summary` | Rule metadata | Summary/brief description |
| `rule_threat` | Rule metadata | Type of threat/behavior detected |
| `rule_severity` | Rule metadata | Severity level (HIGH, MEDIUM, LOW) |
| `rule_category` | Rule metadata | Category/classification of rule |
| `rule_author` | Rule metadata | Author/creator of the rule |
| `alert_count` | Aggregation | Number of alerts triggered by this rule |
| `last_trigger_time` | Rule metadata | Last timestamp rule was triggered |
| `estimated_daily_gb` | Calculation | Estimated daily data volume in GB |

### Event Results Query Output

| Column Name | Source | What It Shows |
|-------------|--------|---------------|
| `log_type` | Metadata | Log source type |
| `event_type` | Metadata | Behavior category |
| `product_event_type` | Metadata | Specific event ID |
| `event_count` | Aggregation | Total occurrences of this combination |
| `sample_host` | Metadata | Example hostname where event occurred |

### Log Volume Query Output

| Column Name | Source | What It Shows |
|-------------|--------|---------------|
| `log_type` | Metadata | Log source type |
| `week` | Timestamp function | ISO week start date (YYYY-MM-DD) |
| `event_count` | Aggregation | Events in that log type for that week |
| `week_gigabytes` | Calculation | Data volume in GB for that week |
| `week_array` | Aggregation | Array of unique weeks (usually 1 per row) |

---

## ⚠️ Troubleshooting

### "Could not find file" Error

**Problem:** Script can't locate CSV files

**Solutions:**
1. ✅ Verify file names are spelled exactly as shown
2. ✅ Check files are in Downloads folder
3. ✅ Confirm file extensions are `.csv` (not `.xlsx` or `.txt`)
4. ✅ Use **file browser dialog** - don't type file names manually

---

### Query Returns No Results

**Problem:** Query runs but shows 0 rows

**Possible Causes:**
- Query time range is too restrictive
- Filters are excluding all data
- No events match the criteria
- Wrong query syntax

**Solutions:**
1. Check SecOps has data ingestion enabled
2. Run a simpler test query: `metadata.log_type != ""` 
3. Verify log sources are configured
4. Check time range settings in query
5. Contact SecOps admin if still no data

---

### "Unterminated f-string" Error

**Problem:** Python script won't run with syntax error

**Solution:**
- Re-download `compare_unmapped_events.py` from outputs
- Current version is fixed (v2.1)

---

### File Shows as Excel Workbook Instead of CSV

**Problem:** File downloaded as `.xlsx` or Excel format

**Solution:**
1. Open file in Excel
2. Use **File** > **Save As**
3. Select format: **CSV (Comma delimited) (*.csv)**
4. Save as `detection_results.csv`

---

## 💡 Best Practices

✅ **DO:**
- Export fresh data weekly/monthly for trend analysis
- Verify file sizes are reasonable (>1KB each)
- Keep backups of analysis files
- Document the date range of your analysis
- Compare multiple time periods to track improvements

❌ **DON'T:**
- Modify CSV files manually before running script
- Delete rows or columns from exported CSVs
- Use old/archived CSV files without checking dates
- Open CSVs in Excel and save - may corrupt encoding
- Change file names after export

---

## 📈 Recommended Data Ranges

**For Accurate Analysis:**

| Duration | Use Case | Notes |
|----------|----------|-------|
| 1 week | Quick test/demo | Good for testing script |
| 2-4 weeks | Baseline analysis | Captures normal operation |
| 1-3 months | Trend analysis | Good for rule improvement |
| 3-6 months | Comprehensive audit | Captures seasonal patterns |

**Note:** Longer time periods may include thousands of event combinations.

---



- [ ] Downloaded detection_results.csv from Step 2 query
- [ ] Downloaded event_results.csv from Step 3 query
- [ ] Downloaded log_volume.csv from Step 1 query (optional)
- [ ] All files in Downloads folder
- [ ] File names match exactly (case-sensitive)
- [ ] All files contain data (not empty)
- [ ] No files are currently open in Excel/text editor
- [ ] Python script (compare_unmapped_events.py) is installed
- [ ] Python 3.6+ is installed and accessible
- [ ] Ready to run: `python compare_unmapped_events.py`



**If queries don't work:**
1. Verify query syntax matches exactly
2. Check SecOps documentation for current query syntax
3. Test with simpler query first
4. Contact Google SecOps support

**If script doesn't work:**
1. Verify file names and locations
2. Check Python version (3.6+)
3. Verify CSV file format
4. Review HOW_TO_USE_SCRIPT.md troubleshooting section

**For interpretation help:**
See DETECTION_COVERAGE_ANALYSIS_GUIDE.md for full analysis methodology

---

## 📄 Summary

1. **Log in to Google SecOps**
2. **Run 3 queries** (or 2 if skipping optional log volume)
3. **Export as CSV** from each query
4. **Rename files** to exact names shown
5. **Place in Downloads** folder
6. **Run Python script**: `python compare_unmapped_events.py`
7. **Select files** when prompted
8. **Review HTML report** that auto-opens in browser

Done! ✅

---


**Version:** 1.1  
**Last Updated:** January 15, 2026  
**For Script Version:** 2.2 (compare_unmapped_events.py) - With PDF Export Support

### Key Features in v2.2:

✨ **Automatic PDF Generation**
- Script generates both HTML and PDF reports simultaneously
- PDF download button embedded in HTML report
- Download directly from browser or from Downloads folder
- Fallback: Use browser Print > Save as PDF if weasyprint not installed

✨ **Date Range Tracking**
- Automatically detects data period from log volumes
- Displays week/month information in report header and log volume section
- Example: "Jan 11 - Feb 22, 2026 (6 weeks)"

✨ **Complete File Naming Guide**
- This guide shows exact filenames required by the script
- Includes download instructions from Google SecOps
- Step-by-step query setup

For questions or updates, refer to HOW_TO_USE_SCRIPT.md

---

## 🚀 Running the Script & Downloading Results

### Step 1: Run the Python Script

**Windows:**
```batch
cd Downloads
python compare_unmapped_events.py
```

**macOS/Linux:**
```bash
cd ~/Downloads
python3 compare_unmapped_events.py
```

### Step 2: File Selection Dialogs

When you run the script, three file dialogs will appear in sequence:

**Dialog 1: Detection Results**
```
Title: "Select Detection Results CSV"
Action: Click on "detection_results.csv" and click Open
```

**Dialog 2: Event Results**
```
Title: "Select Event Results CSV"  
Action: Click on "event_results.csv" and click Open
```

**Dialog 3: Log Volume (Optional)**
```
Title: "Select Log Volume CSV (optional)"
Action: Click on "log_volume.csv" and click Open
OR: Click "Cancel" to skip (this file is optional)
```

### Step 3: Report Generation

The script will:
1. Process your CSV files (takes 5-10 seconds)
2. Show summary statistics in the console window
3. Automatically open the HTML report in your default browser

Console output will show:
```
SUMMARY STATISTICS
================================================================================
Total unique event combinations: 165
Mapped to rules: 95
NOT mapped to rules: 70
Coverage: 57.6%
Data period: Jan 11 - Feb 22, 2026 (6 weeks)
```

### Step 4: Download Report as PDF

The HTML report will open in your browser with a **red "📥 Download as PDF" button** in the header.

**To save as PDF:**

**Chrome/Chromium/Edge:**
1. Click the **"📥 Download as PDF"** button
2. Print dialog opens
3. In the printer dropdown, select **"Save as PDF"**
4. Click **"Save"** button
5. Choose your save location
6. File saves as PDF to Downloads folder

**Firefox:**
1. Click the **"📥 Download as PDF"** button
2. Print dialog opens
3. Look for **"Print to File"** checkbox or dropdown option
4. Select **PDF** format
5. Click **"Save"**

**Safari:**
1. Click the **"📥 Download as PDF"** button
2. Look at **bottom left** of print dialog
3. Click **PDF** dropdown menu
4. Select **"Save as PDF"**
5. Choose location and filename

**Alternative - Manual Print to PDF:**

On any browser:
1. Press **Ctrl+P** (Windows) or **Cmd+P** (macOS)
2. Look for printer dropdown, select **"Save as PDF"**
3. Adjust page settings if needed (usually defaults are fine)
4. Click **"Save"** or **"Print"**
5. Choose save location

### PDF Output Details

**File Information:**
- Default filename: `unmapped_events_report.pdf`
- File size: 200 KB - 500 KB (depending on data volume)
- Page count: Typically 3-8 pages
- Format: Full-color PDF with charts and tables

**What's Included in PDF:**
- ✓ Report title and generation timestamp
- ✓ Data analysis period (e.g., "Jan 11 - Feb 22, 2026 (6 weeks)")
- ✓ Summary statistics cards
- ✓ Coverage percentage bar chart
- ✓ Top log types by volume with visual bars (if provided)
- ✓ Detailed unmapped events organized by log type
- ✓ Professional formatting with colors and styling
- ✓ Print-optimized layout

**Saving Recommendations:**
- Save to: Your Downloads folder or Documents folder
- Naming: `Detection_Analysis_[Date].pdf` (e.g., `Detection_Analysis_2026-01-15.pdf`)
- Keep backups of important reports for trend analysis
- Include data range in filename for future reference

---

## 📊 Complete Workflow Summary

```
1. DOWNLOAD FILES FROM GOOGLE SECOPS
   ├─ Run Detection Rules query (Step 2)
   │  └─ Save as: detection_results.csv
   ├─ Run Raw Events query (Step 3)
   │  └─ Save as: event_results.csv
   └─ Run Log Volume query (Step 1, optional)
      └─ Save as: log_volume.csv

2. PREPARE FILES
   ├─ Verify file names match exactly
   ├─ Place all files in Downloads folder
   └─ Ensure files are not open in other programs

3. RUN PYTHON SCRIPT
   ├─ Open command prompt/terminal
   ├─ Navigate to Downloads folder
   ├─ Run: python compare_unmapped_events.py
   └─ Select CSV files when prompted

4. GENERATE & DOWNLOAD REPORT
   ├─ Script processes files
   ├─ HTML report opens in browser
   ├─ Click "📥 Download as PDF" button
   ├─ Select "Save as PDF" from print dialog
   └─ Save PDF to desired location

5. ANALYZE RESULTS
   ├─ Review HTML report in browser
   ├─ Review PDF copy for sharing/archiving
   └─ Follow DETECTION_COVERAGE_ANALYSIS_GUIDE for next steps
```


---

## 🎯 What's Displayed in the HTML Report (v2.3)

### Section 1: Report Header
- Report title and generation timestamp
- Data period (if log_volume.csv provided)
- "📥 Download as PDF" button

### Section 2: Summary Statistics
- Total event combinations found
- Mapped to rules (detected by existing rules)
- Unmapped combinations (not detected)
- Overall detection coverage percentage

### Section 3: Active Detection Rules ⭐ NEW
A table showing all the detection rules from your CSV:
- **Rule Name** - Name of each detection rule
- **Severity** - Color-coded (Red=HIGH, Orange=MEDIUM, Green=LOW)
- **Category** - What type of threat it detects
- **Alerts** - How many alerts this rule triggered
- **Description** - Brief description of what the rule does

### Section 4: Top Log Types by Volume (if log_volume.csv provided)
- Log type names
- Weekly event counts
- Weekly data volume in GB
- Visual comparison bars

### Section 5: Unmapped Event Combinations (if any exist)
- Events occurring in environment but NOT detected by rules
- Organized by log type
- Shows event type and product event type
- Indicates which combinations need detection rules

---

## 📋 How the Script Works (v2.3)

```
1. Load detection_results.csv
   ├─ Extract all rule information
   └─ Create list of detected event combinations

2. Load event_results.csv  
   ├─ Extract all event combinations
   └─ Create list of all occurring events

3. Load log_volume.csv (optional)
   └─ Extract volume and time period data

4. Compare & Analyze
   ├─ Find events NOT detected by any rule = unmapped
   ├─ Find events detected by rules = mapped
   └─ Calculate coverage percentage

5. Generate HTML Report
   ├─ Display all detection rules from CSV
   ├─ Display log volume (if provided)
   ├─ Display unmapped events
   ├─ Add PDF download button
   └─ Open in browser

6. User Downloads PDF
   └─ Click "📥 Download as PDF" button
   └─ Save to computer
```

