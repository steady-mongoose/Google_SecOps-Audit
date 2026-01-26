# Complete Revision: How to Get rules.json via SDK

## Critical Update

**rules.json cannot be exported from the Dashboard.**

It must be obtained using the **Google SecOps SDK** - a Python-based tool that queries your SecOps environment.

This is different from the CSV files, which are simple Dashboard exports.

---

## What Changed

### Original (WRONG)
```
Export rules.json from SecOps Dashboard
→ Click Export
→ Choose JSON format
→ Download
```

### Corrected (RIGHT)
```
Install Google SecOps SDK
→ Authenticate with credentials
→ Run Python script to query SecOps
→ Script generates rules.json
→ File saved locally
```

---

## Why SDK is Required

The Google SecOps API (which rules.json uses) is accessed through:
- **SDK:** Software Development Kit
- **Language:** Python
- **Method:** Direct API calls to SecOps backend
- **Not available:** Through Dashboard UI

---

## Quick Start: Getting rules.json via SDK

### Step 1: Install SDK

```bash
pip install google-cloud-securityops --break-system-packages
```

### Step 2: Get Credentials

Download service account credentials from Google Cloud Console:
1. Google Cloud Console
2. Service Accounts
3. Create or select service account
4. Download JSON key
5. Save as `credentials.json`

### Step 3: Create Export Script

Create file named `export_rules.py`:

```python
#!/usr/bin/env python3
"""
Export detection rules from Google SecOps to JSON file
Required for rule comparison analysis
"""

import json
import sys
from datetime import datetime
from google.cloud import securityops_v1
from google.oauth2 import service_account


def export_rules_to_json(credentials_file, output_file="rules.json"):
    """
    Export all detection rules from Google SecOps
    
    Args:
        credentials_file: Path to service account credentials JSON
        output_file: Output filename for rules export
    """
    
    print("=" * 80)
    print("Google SecOps Rules Export")
    print("=" * 80)
    print()
    
    # Step 1: Load credentials
    try:
        with open(credentials_file) as f:
            credentials_dict = json.load(f)
        project_id = credentials_dict['project_id']
        print(f"✓ Credentials loaded from: {credentials_file}")
        print(f"✓ Project ID: {project_id}")
    except FileNotFoundError:
        print(f"✗ Credentials file not found: {credentials_file}")
        return None
    except json.JSONDecodeError:
        print(f"✗ Credentials file is not valid JSON: {credentials_file}")
        return None
    except KeyError:
        print(f"✗ Credentials missing 'project_id' field")
        return None
    
    print()
    
    # Step 2: Authenticate
    try:
        credentials = service_account.Credentials.from_service_account_info(credentials_dict)
        client = securityops_v1.QueryClient(credentials=credentials)
        print("✓ Authenticated with Google SecOps")
    except Exception as e:
        print(f"✗ Authentication failed: {e}")
        return None
    
    print()
    
    # Step 3: Query rules
    print("Querying detection rules from SecOps...")
    print("(This may take 1-3 minutes depending on rule count)")
    print()
    
    query = """
    detection.detection.rule_name != ""
    
    $rule_name = detection.detection.rule_name
    $rule_description = detection.detection.description
    $rule_severity = detection.detection.severity
    $rule_state = detection.detection.alert_state
    $rule_type = detection.detection.rule_type
    
    not $rule_name = /(STAGE_|DEV_|_PR_)/
    
    match:
      $rule_name
    
    outcome:
      $count = count_distinct(detection.id)
    
    order:
      $count desc
    
    limit:
      1000
    """
    
    try:
        request = securityops_v1.RunAsyncQueryRequest(
            parent=f"projects/{project_id}/locations/us",
            query=query
        )
        
        print("⏳ Executing query...")
        operation = client.run_async_query(request=request)
        print("⏳ Waiting for results...")
        results = operation.result(timeout=300)
        
        print("✓ Query complete")
    except Exception as e:
        print(f"✗ Query failed: {e}")
        return None
    
    print()
    
    # Step 4: Process results
    print("Processing results...")
    rules = []
    row_count = 0
    
    for row in results:
        row_count += 1
        rule_entry = {
            "name": row.get('rule_name', ''),
            "description": row.get('rule_description', ''),
            "severity": row.get('rule_severity', ''),
            "state": row.get('rule_state', ''),
            "type": row.get('rule_type', ''),
            "count": row.get('count', 0)
        }
        
        if rule_entry['name']:  # Only add if has name
            rules.append(rule_entry)
    
    print(f"✓ Processed {row_count} rows")
    print(f"✓ Extracted {len(rules)} rules")
    
    print()
    
    # Step 5: Save to file
    print("Saving to JSON file...")
    
    output_data = {
        "rules": rules,
        "metadata": {
            "exportDate": datetime.now().isoformat(),
            "totalRules": len(rules),
            "project": project_id
        }
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"✓ Rules saved to: {output_file}")
        
        # Get file info
        import os
        file_size = os.path.getsize(output_file)
        size_mb = file_size / (1024 * 1024)
        
        print(f"✓ File size: {size_mb:.2f} MB")
    except Exception as e:
        print(f"✗ Failed to save file: {e}")
        return None
    
    print()
    print("=" * 80)
    print("✓ Export complete!")
    print("=" * 80)
    print()
    print(f"Use {output_file} with customer_audit_v4.py")
    print()
    
    return output_file


if __name__ == "__main__":
    # Get credentials file from command line or use default
    credentials_file = sys.argv[1] if len(sys.argv) > 1 else "credentials.json"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "rules.json"
    
    result = export_rules_to_json(credentials_file, output_file)
    
    if result:
        print(f"✓ SUCCESS: {result} is ready to use")
        sys.exit(0)
    else:
        print("✗ FAILED: Could not export rules")
        sys.exit(1)
```

### Step 4: Run the Script

```bash
python3 export_rules.py credentials.json
```

### Step 5: Verify

```bash
# Check file exists
ls -lh rules.json

# Verify it's valid JSON
python3 -c "import json; json.load(open('rules.json')); print('Valid JSON')"

# Check rule count
python3 << 'EOF'
import json
with open('rules.json') as f:
    data = json.load(f)
    print(f"Total rules: {len(data['rules'])}")
    print(f"Export date: {data['metadata']['exportDate']}")
EOF
```

### Result

You now have `rules.json` file ready to use with `customer_audit_v4.py`

---

## What Each Step Does

### Step 1: Install SDK
- Downloads Google SecOps Python library
- Installs all dependencies
- One-time setup

### Step 2: Get Credentials
- Creates service account in Google Cloud
- Downloads authentication credentials
- Allows Python script to access SecOps API
- Credentials file = your authentication key

### Step 3: Create Script
- Python script that queries SecOps API
- Uses credentials to authenticate
- Sends query to get all rules
- Processes results into JSON format

### Step 4: Run Script
- Script connects to Google SecOps
- Queries your rules
- Saves results to rules.json
- Shows progress and success/error messages

### Step 5: Verify
- Confirms file was created
- Checks it's valid JSON
- Shows rule count and export date
- File ready for analysis tool

---

## Detailed Step-by-Step: SDK Installation & Setup

### Prerequisites

Before starting, you need:
- ✅ Python 3.6 or higher installed
- ✅ Access to Google Cloud Console
- ✅ Service account with SecOps permissions
- ✅ Internet connection

### Install Python SDK

**On Windows:**
```bash
python -m pip install google-cloud-securityops --break-system-packages
```

**On macOS/Linux:**
```bash
pip install google-cloud-securityops --break-system-packages
# OR
pip3 install google-cloud-securityops --break-system-packages
```

**Verify Installation:**
```bash
python3 -c "from google.cloud import securityops_v1; print('SDK installed successfully')"
```

### Get Credentials

#### Method 1: Service Account (Recommended)

1. **Go to Google Cloud Console**
   - https://console.cloud.google.com
   - Select your project

2. **Navigate to Service Accounts**
   - Menu → IAM & Admin → Service Accounts

3. **Create or Select Service Account**
   - Click "Create Service Account" (if needed)
   - Name: something like "secops-rules-export"
   - Click "Create and Continue"

4. **Grant Permissions**
   - Role: "Chronicle Viewer" or "Chronicle Editor"
   - Click "Continue"

5. **Create Key**
   - Click on service account you created
   - Tab: "Keys"
   - "Create New Key"
   - Type: JSON
   - Click "Create"
   - JSON file downloads automatically

6. **Save as credentials.json**
   - Rename downloaded file to: `credentials.json`
   - Save in your working directory
   - Keep secure (it's your authentication key!)

#### Method 2: Application Default Credentials

```bash
gcloud auth application-default login
```

This uses your gcloud authentication instead of a service account file.

### File Organization

```
your-working-directory/
├── credentials.json        (downloaded from Google Cloud)
├── export_rules.py         (Python script)
├── rules.json             (output - generated by script)
├── detection_results.csv  (from SecOps Dashboard)
├── event_results.csv      (from SecOps Queries)
└── log_volume.csv         (from SecOps Queries - optional)
```

---

## Complete Workflow: Getting All 4 Files

### File 1: rules.json (via SDK - NEW!)

```bash
# 1. Install SDK (one-time)
pip install google-cloud-securityops --break-system-packages

# 2. Get credentials.json from Google Cloud Console
# (See above)

# 3. Create export_rules.py (use script from above)

# 4. Run the script TODAY
python3 export_rules.py credentials.json

# 5. Verify
ls -lh rules.json
```

### File 2: detection_results.csv (via Dashboard)

```
1. Go to SecOps Dashboard
2. Run detection rules query
3. Export as CSV
4. Save as: detection_results.csv
```

### File 3: event_results.csv (via SecOps Queries)

```
1. Go to SecOps Queries
2. Run events query
3. Export as CSV
4. Save as: event_results.csv
```

### File 4: log_volume.csv (via SecOps Queries - Optional)

```
1. Go to SecOps Queries
2. Run log volume query
3. Export as CSV
4. Save as: log_volume.csv
```

### Run Analysis

```bash
python3 customer_audit_v4.py
# Then select all 4 files when prompted
```

---

## Automating rules.json Export (Optional)

### Daily Automated Export

Create a script that runs daily:

```bash
#!/bin/bash
# run_export_daily.sh

cd /path/to/working/directory

# Run export with today's date in filename
python3 export_rules.py credentials.json rules.json

# Show success
echo "Rules exported: $(date)"
```

### Linux Cron Job

Add to crontab:

```bash
# Export rules daily at midnight
0 0 * * * /path/to/run_export_daily.sh

# Edit crontab:
crontab -e
```

### Windows Task Scheduler

1. Create batch file: `export_rules.bat`
   ```batch
   cd C:\path\to\working\directory
   python3 export_rules.py credentials.json
   ```

2. Create scheduled task
   - Task Scheduler → Create Basic Task
   - Name: "Export SecOps Rules"
   - Trigger: Daily at midnight
   - Action: Run script: export_rules.bat

---

## Troubleshooting SDK Setup

### Issue: "ModuleNotFoundError: No module named 'google'"

**Cause:** SDK not installed

**Fix:**
```bash
pip install google-cloud-securityops --break-system-packages
```

---

### Issue: "Authentication failed" or "Unauthorized"

**Cause:** Credentials invalid or missing permissions

**Fix:**
1. Verify credentials.json exists in working directory
2. Verify it's valid JSON:
   ```bash
   python3 -c "import json; json.load(open('credentials.json'))"
   ```
3. Verify service account has correct permissions:
   - Google Cloud Console
   - IAM & Admin → Service Accounts
   - Check role assigned (should be Viewer or Editor)

---

### Issue: "Query returned no rules"

**Cause:** Query syntax or access issue

**Fix:**
1. Verify you have rules in SecOps:
   - Log into SecOps Dashboard
   - Check Rules section
   - Confirm rules exist

2. Try simpler query:
   ```python
   query = """
   detection.detection.rule_name != ""
   match:
     $rule_name = detection.detection.rule_name
   limit:
     10
   """
   ```

3. Check project_id:
   ```bash
   python3 -c "import json; print(json.load(open('credentials.json'))['project_id'])"
   ```

---

### Issue: "Timeout waiting for query"

**Cause:** Query taking too long (large rule set)

**Fix:**
1. Increase timeout in script:
   ```python
   results = operation.result(timeout=600)  # 10 minutes
   ```

2. Run during off-peak hours

3. Contact SecOps team for assistance

---

## Reference Documentation

### Official Google Documentation
- **SecOps SDK Libraries:** https://docs.cloud.google.com/chronicle/docs/libraries
- **SecOps API Reference:** https://cloud.google.com/python/docs/reference/securityops/latest

### Community Guide
- **Getting Started Guide:** https://medium.com/@thatsiemguy/getting-started-with-the-google-secops-sdk-69effdde5978

---

## Important Reminders

⚠️ **Fresh TODAY**
- Run export_rules.py TODAY before analysis
- Don't use old rules.json from previous months
- Rules change daily - export each time

⚠️ **For THIS Customer**
- Use service account with access to THIS customer's SecOps
- Each customer has different rules
- Don't share rules.json between customers

⚠️ **Credentials Security**
- Keep credentials.json secure
- Don't share or commit to version control
- Treat like password (it's your authentication key)
- Delete if service account is deleted

⚠️ **SDK Setup**
- One-time setup (install SDK)
- Credentials needed for each customer
- Script generates fresh rules.json each time

---

## Summary

| Aspect | Details |
|--------|---------|
| **How** | Python SDK + script |
| **Install** | `pip install google-cloud-securityops` |
| **Credentials** | Service account JSON from Google Cloud |
| **Script** | Python script that queries SecOps API |
| **Freshness** | Run TODAY before analysis |
| **Customer** | Each customer needs separate export |
| **Result** | rules.json file ready for analysis |

---

**Ready? Follow the Quick Start above, or detailed steps for full setup.** ✅
