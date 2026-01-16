# How to Use: compare_unmapped_events.py

## Quick Start

This Python script compares your detection results against raw events to identify coverage gaps and generates a beautiful HTML report.

## Requirements

✅ **Python 3.6 or higher**  
✅ **tkinter** (usually comes pre-installed with Python)  
✅ **Two CSV files** from your Google SecOps queries:
- `detection_results.csv` (from Step 2 query)
- `event_results.csv` (from Step 3 query)

---

## Step 1: Prepare Your CSV Files

### File 1: detection_results.csv

**Source:** Step 2 - Detection Rules Query (from Dashboard)

**How to create:**
1. Go to Google SecOps Dashboard
2. Run the detection rules query (see guide Step 2)
3. Export results as CSV
4. **Save as:** `detection_results.csv`
5. **Location:** Your Downloads folder (or any accessible location)

**Expected columns:**
- `log_type` or `Logtype` or `LogType`
- `event_type` or `Eventtype` or `EventType`
- `product_event_type` or `Productevent` or `ProductEvent`
- (Other columns like rule_name, alert_count, etc. are optional)

### File 2: event_results.csv

**Source:** Step 3 - Raw Events Query

**How to create:**
1. Run the raw events query in Google SecOps
2. Export results as CSV
3. **Save as:** `event_results.csv`
4. **Location:** Your Downloads folder (or any accessible location)

**Expected columns:**
- `log_type`
- `event_type`
- `product_event_type`
- (Other columns like event_count, host_list, etc. are optional)

### File 3: log_volume.csv (OPTIONAL)

**Source:** Step 1 - Log Volume Query

**How to create:**
1. Run the log volume query in Google SecOps (Step 1 from guide)
2. Export results as CSV
3. **Save as:** `log_volume.csv`
4. **Location:** Your Downloads folder (or any accessible location)

**Expected columns:**
- `log_type`
- `event_count`
- `week_gigabytes`
- `week`
- (Other columns are optional)

**Purpose:** Shows top log types by volume in a visual chart on the HTML report. This is **OPTIONAL** - the script works fine without it.

---

## Step 2: Run the Script

### On Windows:

**Option A: Command Prompt**
```bash
cd Downloads
python compare_unmapped_events.py
```

**Option B: Double-click**
1. Place `compare_unmapped_events.py` in your Downloads folder
2. Double-click the file
3. Python will execute it

### On macOS/Linux:

**Terminal:**
```bash
cd ~/Downloads
python3 compare_unmapped_events.py
```

Or:
```bash
chmod +x compare_unmapped_events.py
./compare_unmapped_events.py
```

---

## Step 3: Select Your Files

When you run the script:

### File Dialog 1: Detection Results
```
[File browser opens]
Title: "Select Detection Results CSV (granular rule mappings)"
Action: Navigate to and select detection_results.csv
Click: Open
```

### File Dialog 2: Event Results
```
[File browser opens]
Title: "Select Event Results CSV (raw events)"
Action: Navigate to and select event_results.csv
Click: Open
```

### File Dialog 3: Log Volume (OPTIONAL)
```
[File browser opens]
Title: "Select Log Volume CSV (optional - top log types by volume)"
Action: Navigate to and select log_volume.csv
OR: Click Cancel to skip (this file is optional)
```

**Note:** If you skip this file, the script will still work - you just won't see the log volume chart in the report.

---

## Step 4: Review the Output

### Console Output

```
================================================================================
YARAL Event Mapping Comparison Tool - Granular Detection Analysis
================================================================================

Please select Detection Results CSV file...
(This should be detection_results.csv from Step 2)
✓ Selected: detection_results.csv

Please select Event Results CSV file...
(This should be event_results.csv from Step 3)
✓ Selected: event_results.csv

Please select Log Volume CSV file (OPTIONAL)...
(This should be log_volume.csv from Step 1)
(You can click Cancel to skip this file)
✓ Selected: log_volume.csv

Processing files...

Loading detection results...
  Processed 116 rows
✓ Loaded 95 unique (log_type, event_type, product_event_type) combinations

Loading event results...
  Processed 165 rows
✓ Loaded 165 unique (log_type, event_type, product_event_type) combinations

Loading log volume data...
  Processed 12 rows
✓ Loaded 12 log volume records

Comparing results...



Generating HTML report...

✓ HTML report saved to:
  /Users/yourname/Downloads/unmapped_events_report.html

✓ Report generated successfully!
✓ Opening report in default browser...

================================================================================
Done! The HTML report has been opened in your browser.
================================================================================
```

### HTML Report

A browser window opens automatically showing:

**Summary Section:**
- Total Combinations: 165
- Mapped to Rules: 95
- Unmapped Combinations: 70
- Detection Coverage: 57.6%

**⭐ Data Period (NEW FEATURE):**
- Displayed in the header below the generation timestamp
- Shows the date range covered by the analysis
- Format: "📅 Data Period: Jan 11 - Feb 22, 2026 (6 weeks)" or "📅 Data Period: Jan 11, 2026 (1 week)"
- Automatically calculated from the log_volume.csv data
- Only shown if log_volume.csv is provided

**Coverage Bar:**
Visual representation of detection coverage percentage

**Top Log Types by Volume (if log_volume.csv provided):**
A professional table showing:
- Log Type name
- Weekly Events count
- Weekly Volume (GB)
- Visual volume bar chart comparing log type sizes
- **📅 Data Period displayed above the table** - Shows exact date range and duration in weeks/months

Example:
```
LOG TYPE            WEEKLY EVENTS   WEEKLY VOLUME   VOLUME COMPARISON
WINEVTLOG           1,245,000       48.92 GB        [████████████] 100%
OFFICE_365          542,100         22.15 GB        [██████] 45%
FORTINET_FIREWALL   823,500         35.67 GB        [████████] 73%
...
```

This chart helps identify which log types are highest volume and should prioritize detection coverage.

**Coverage Overview:**
Visual bar showing percentage of events mapped to detection rules

**Detailed Unmapped Events Tables:**
For each log type, a table showing:
- Event Type
- Product Event Type
- Status (Unmapped)

Example:
```
WINEVTLOG (28 unmapped events)
├─ USER_LOGIN + 4625 (Failed Logon)
├─ USER_LOGIN + 4768 (Kerberos TGT Requested)
├─ PROCESS_LAUNCH + 4688 (Process Created)
└─ ...

OFFICE_365 (15 unmapped events)
├─ USER_LOGIN + UserLoginFailed
├─ EMAIL_SEND + Success


### Where the Script Looks for Files:

1. **File Dialog Default Location:** Your Downloads folder
2. **You can select files from anywhere** - the script uses file explorer dialogs

### Where Results Are Saved:

- **HTML Report:** `~/Downloads/unmapped_events_report.html`
- **Automatically opened** in your default browser

---

## Troubleshooting

### "No detection file selected. Exiting."

**Problem:** You clicked Cancel instead of selecting a file

**Solution:** Run the script again and select the file properly

---

### "Failed to load files. Exiting."

**Problem:** CSV files are corrupt or columns don't match expected names

**Solution:**
1. Open the CSV in Excel/text editor
2. Verify column names:
   - Detection file should have: `log_type`, `event_type`, `product_event_type`
   - Event file should have: `log_type`, `event_type`, `product_event_type`
3. Ensure file is not open in another program
4. Try again

---

### "Error loading detection file: [error message]"

**Problem:** File encoding or permission issue

**Solution:**
1. Check file is readable (not locked by another program)
2. Try re-exporting the CSV from Google SecOps
3. Ensure file is UTF-8 encoded

---

### File Dialog Doesn't Appear

**Problem:** tkinter not installed or not working

**Solution (Windows):**
```bash
python -m pip install --upgrade tk
```

**Solution (macOS):**
```bash
brew install python-tk@3.9
```

**Solution (Linux):**
```bash
sudo apt-get install python3-tk
```

---

### Report Opens But Shows No Data

**Problem:** Both CSV files processed but no unmapped events found

**Interpretation:** All events in your environment ARE being detected! ✅

This is excellent - it means 100% coverage.

---

### Report Shows Very High Unmapped Count (>80%)

**Problem:** Many unmapped events detected

**Interpretation:** You have detection coverage gaps that need investigation

**Next Steps:**
1. Review the detailed tables in the report
2. Check which log types have the most gaps
3. See the main guide (Step 6-8) for how to address gaps

---

## Script Features

✅ **Automatic file browsing** - No command-line file path needed  
✅ **Column name flexibility** - Handles different CSV column naming conventions  
✅ **Diagnostic output** - Shows column names found and sample data  
✅ **Beautiful HTML report** - Professional formatting with charts  
✅ **Auto browser opening** - Report opens automatically in your default browser  
✅ **Error handling** - Clear error messages if something goes wrong  

---

## What the Script Does

### Step 1: Load Detection Results
- Reads CSV file containing detected event combinations
- Extracts: (log_type, event_type, product_event_type)
- Creates set of all detected combinations

### Step 2: Load Event Results
- Reads CSV file containing all raw events
- Extracts: (log_type, event_type, product_event_type)
- Creates set of all occurring combinations

### Step 3: Compare Sets
```
Unmapped = All Events - Detected Events
```

### Step 4: Generate Report
- Groups unmapped events by log type
- Creates color-coded HTML with tables
- Calculates coverage percentage
- Shows summary statistics

### Step 5: Save and Display
- Saves HTML report to Downloads folder
- Opens report in default browser automatically

---

## Example Workflow

```
1. Export detection_results.csv from Google SecOps Step 2 query
   └─ Save to Downloads

2. Export event_results.csv from Google SecOps Step 3 query
   └─ Save to Downloads

3. Run the script:
   python compare_unmapped_events.py

4. Select detection_results.csv
   └─ Click Open

5. Select event_results.csv
   └─ Click Open

6. Wait 5-10 seconds for processing

7. HTML report opens automatically in browser

8. Review unmapped events in report

9. Follow main guide (Steps 6-8) to address gaps
```

---

## Advanced Usage

### Running with Specific File Paths

If you want to run the script with pre-selected files (advanced):

**Option 1: Copy files next to script**
- Place `compare_unmapped_events.py` in same folder as CSVs
- Run script - it will look in that folder first

**Option 2: Modify script** (advanced users)
- Edit the `main()` function
- Replace file dialog with hardcoded paths:
```python
detection_file = "/path/to/detection_results.csv"
event_file = "/path/to/event_results.csv"
```

---

## Interpreting Results

### Coverage Percentage

- **90-100%:** Excellent coverage ✅
- **70-90%:** Good coverage, some gaps
- **50-70%:** Moderate gaps, review needed
- **<50%:** Significant gaps, action required

### High-Risk Unmapped Events

Monitor especially for:
- `4625` (Failed login attempts)
- `4672` (Privilege escalation)
- `4722-4728` (Account modifications)
- `DELETE` category events
- `ACCESS_DENIED` events

### Low-Risk Unmapped Events

Usually acceptable:
- `4688` (Process launched)
- `4663` (File accessed)
- Status/informational events
- Routine application operations

---

## Next Steps After Running Script

1. **Review the HTML report** - Understand what's unmapped
2. **Check enabled rules** - See main guide Step 6 for dormant rules
3. **Identify gaps** - Determine which unmapped events are high-risk
4. **Create missing rules** - Implement rules for critical gaps
5. **Re-run script** - Verify improvement in coverage after changes

---

## Support

**For script errors:**
1. Check Requirements section above
2. Verify CSV file format and column names
3. Review Troubleshooting section
4. Check console output for specific error message

**For interpretation questions:**
See the main "DETECTION_COVERAGE_ANALYSIS_GUIDE.md" or PDF

---



---

## License & Author

**Author:** Security Operations Team  
**Purpose:** Identify detection coverage gaps in security environments  
**Use:** Internal security testing and analysis

---

**Ready to run? Start with Step 1: Prepare Your CSV Files above! ⬆️**

---

## 🆕 v2.3 - Active Detection Rules Display

**New Feature: The HTML report now displays all detection rules loaded from your CSV!**

### What's New:

The report now includes a complete **"🚨 Active Detection Rules"** section that shows:

- **Rule Name** - The name of each detection rule
- **Severity** - Color-coded indicator (Red=HIGH, Orange=MEDIUM, Green=LOW)
- **Category** - What type of threat/behavior the rule detects
- **Alert Count** - How many times the rule triggered
- **Description** - What the rule does (first 100 characters)

### Where It Appears:

In the HTML report, you'll see this section **after the Coverage Overview** and **before the Log Volume section**.

### Example:

```
🚨 ACTIVE DETECTION RULES

Rule Name                          | Severity | Category      | Alerts | Description
WIN_Failed_Login_Attempt          | HIGH     | Authentication| 1,245  | Detects multiple failed login...
Office365_Suspicious_Activity     | HIGH     | Office 365    | 567    | Detects suspicious user activity...
Firewall_Anomaly_Detection        | MEDIUM   | Network       | 234    | Detects firewall rule violations...
```

### Severity Colors:

- 🔴 **HIGH** (Red) - Critical threats that need immediate attention
- 🟠 **MEDIUM** (Orange) - Important threats that should be monitored  
- 🟢 **LOW** (Green) - Lower priority threats

---

## Query Reference (v2.3)

The detection_results.csv should come from this query:

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

See **DOWNLOAD_AND_PREPARE_FILES.md** for complete download instructions.

