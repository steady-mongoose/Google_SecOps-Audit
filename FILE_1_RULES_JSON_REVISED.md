# File 1: rules.json (REQUIRED - FRESH TODAY)

## ⚠️ IMPORTANT: SDK Required

**rules.json requires the Google SecOps SDK - it cannot be exported from the Dashboard.**

This is a critical difference from the CSV files, which are simple Dashboard exports.

---

## What rules.json Is

JSON export of ALL your detection rules from Google SecOps:
- All rule names and IDs
- Enabled/disabled status
- Severity levels
- Rule descriptions
- Rule logic/conditions
- Author and dates
- Categories and tags

---

## How to Get rules.json

### Option 1: Using Google SecOps SDK (Recommended)

The official Google SecOps SDK is the proper way to export rules.

**Requirements:**
- Python 3.6+
- Google Cloud SDK installed
- Credentials/authentication to SecOps
- Internet connection

**Documentation:**
https://docs.cloud.google.com/chronicle/docs/libraries

**Steps:**

1. **Install the Google SecOps SDK**
   ```bash
   pip install google-cloud-securityops --break-system-packages
   ```

2. **Get credentials**
   - Download service account credentials from Google Cloud Console
   - Save as `credentials.json`
   - OR use your existing SecOps credentials

3. **Create Python script to export rules**
   
   Create file: `export_rules.py`
   ```python
   #!/usr/bin/env python3
   """
   Export detection rules from Google SecOps
   """
   
   import json
   from google.cloud import securityops_v1
   from google.oauth2 import service_account
   
   def export_rules_to_json(credentials_file, output_file="rules.json"):
       """
       Export all rules from Google SecOps to JSON file
       """
       
       # Load credentials
       with open(credentials_file) as f:
           credentials_dict = json.load(f)
       
       project_id = credentials_dict['project_id']
       credentials = service_account.Credentials.from_service_account_info(credentials_dict)
       
       # Create client
       client = securityops_v1.QueryClient(credentials=credentials)
       
       print("Connecting to Google SecOps...")
       
       # Query rules
       print("Fetching rules...")
       query = """
       detection.detection.rule_name != ""
       $rule_name = detection.detection.rule_name
       $rule_description = detection.detection.description
       $rule_severity = detection.detection.severity
       $rule_state = detection.detection.alert_state
       $rule_type = detection.detection.rule_type
       
       match:
         $rule_name
       
       outcome:
         $count = count_distinct(detection.id)
       
       limit:
         1000
       """
       
       request = securityops_v1.RunAsyncQueryRequest(
           parent=f"projects/{project_id}/locations/us",
           query=query
       )
       
       operation = client.run_async_query(request=request)
       results = operation.result(timeout=300)
       
       # Process results
       rules = []
       for row in results:
           rules.append({
               "name": row.get('rule_name', ''),
               "description": row.get('rule_description', ''),
               "severity": row.get('rule_severity', ''),
               "state": row.get('rule_state', ''),
               "type": row.get('rule_type', ''),
               "count": row.get('count', 0)
           })
       
       # Save to file
       output_data = {
           "rules": rules,
           "metadata": {
               "exportDate": str(datetime.now()),
               "totalRules": len(rules),
               "project": project_id
           }
       }
       
       with open(output_file, 'w') as f:
           json.dump(output_data, f, indent=2)
       
       print(f"✓ Exported {len(rules)} rules to {output_file}")
       return output_file
   
   if __name__ == "__main__":
       import sys
       from datetime import datetime
       
       credentials_file = sys.argv[1] if len(sys.argv) > 1 else "credentials.json"
       export_rules_to_json(credentials_file)
   ```

4. **Run the script**
   ```bash
   python3 export_rules.py credentials.json
   ```

5. **Verify rules.json was created**
   ```bash
   ls -lh rules.json
   head -50 rules.json
   ```

**Result:** `rules.json` file in your current directory

---

### Option 2: Backend Linux Host Method (For Server Environments)

If running on a backend Linux host, follow this comprehensive guide:

**Reference Guide:**
https://medium.com/@thatsiemguy/getting-started-with-the-google-secops-sdk-69effdde5978

**Quick Overview:**

1. **On your Linux host:**
   ```bash
   # Install Python SDK
   pip install google-cloud-securityops --break-system-packages
   
   # Authenticate (use service account or gcloud auth)
   gcloud auth application-default login
   # OR
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
   ```

2. **Create export script**
   - See Option 1 script above
   - Or use the guide's example code

3. **Schedule regular exports**
   ```bash
   # Add to crontab for daily export
   0 0 * * * /usr/bin/python3 /path/to/export_rules.py credentials.json
   ```

4. **Get the file to your analysis machine**
   ```bash
   # Copy from server
   scp user@server:/path/to/rules.json ./rules.json
   ```

---

## Troubleshooting SDK Installation

### "ModuleNotFoundError: No module named 'google'"

**Problem:** SDK not installed

**Solution:**
```bash
pip install google-cloud-securityops --break-system-packages
```

---

### "Authentication failed"

**Problem:** Credentials not valid

**Solutions:**
1. Verify credentials.json is valid:
   ```bash
   python3 -c "import json; json.load(open('credentials.json'))"
   ```

2. Use gcloud authentication instead:
   ```bash
   gcloud auth application-default login
   ```

3. Verify service account has SecOps access:
   - Check IAM roles in Google Cloud Console
   - Should have: Viewer or Editor role

---

### "Query returned no rules"

**Problem:** Query didn't find any rules

**Solutions:**
1. Verify you're in correct project:
   ```bash
   gcloud config get-value project
   ```

2. Verify rules exist in SecOps:
   - Log into SecOps Dashboard
   - Check Rules section
   - Confirm you have rules

3. Try simpler query:
   ```
   detection.detection.rule_name != ""
   match:
     $rule_name = detection.detection.rule_name
   limit:
     10
   ```

---

## File Size Reference

Expected rules.json file sizes:

```
100 rules:   ~50-100 KB
300 rules:   ~200-500 KB
500+ rules:  ~500 KB - 2 MB
1000+ rules: ~1-5 MB
```

If your file is much smaller or larger, verify the query ran correctly.

---

## Verification

Before using rules.json, verify it:

```bash
✅ File exists: rules.json

✅ Valid JSON:
python3 -c "import json; json.load(open('rules.json'))" && echo "Valid JSON"

✅ Has content:
python3 << 'EOF'
import json
with open('rules.json') as f:
    data = json.load(f)
    print(f"Rules: {len(data.get('rules', []))}")
    print(f"Sample rule: {data['rules'][0] if data['rules'] else 'None'}")
EOF

✅ Exported TODAY:
stat rules.json | grep Modify
```

---

## Sample rules.json Structure

```json
{
  "rules": [
    {
      "name": "Brute_Force_Detection",
      "description": "Detects multiple failed login attempts",
      "severity": "HIGH",
      "state": "ENABLED",
      "type": "Detection",
      "count": 1245
    },
    {
      "name": "Office365_Suspicious_Activity",
      "description": "Detects suspicious Office 365 user activity",
      "severity": "MEDIUM",
      "state": "ENABLED",
      "type": "Detection",
      "count": 567
    },
    ... more rules ...
  ],
  "metadata": {
    "exportDate": "2025-01-26 10:30:45",
    "totalRules": 342,
    "project": "my-secops-project"
  }
}
```

---

## Key Points

⚠️ **SDK Required**
- Cannot be exported from Dashboard
- Requires Python and SDK installation
- Requires authentication

✅ **Fresh Export**
- Run script TODAY before analysis
- Not a static file from a download
- Gets current rules from SecOps

✅ **Flexibility**
- Run on your machine
- Run on backend server
- Schedule with cron/scheduler
- Automate as needed

✅ **Authentication**
- Use service account credentials
- OR use gcloud authentication
- Must have SecOps access

---

## Next Steps

1. **Install the SDK**
   ```bash
   pip install google-cloud-securityops --break-system-packages
   ```

2. **Get credentials**
   - Download from Google Cloud Console
   - Save as credentials.json

3. **Create export script**
   - Use example from Option 1 above
   - Or follow the Medium guide

4. **Test the export**
   ```bash
   python3 export_rules.py credentials.json
   ls -lh rules.json
   ```

5. **Verify success**
   - Check file exists
   - Verify it's valid JSON
   - Check it has rules

6. **Use with analysis tool**
   - Copy rules.json to same folder as CSVs
   - Run customer_audit_v4.py
   - Select rules.json when prompted

---

## Reference Documentation

- **Google SecOps SDK:** https://docs.cloud.google.com/chronicle/docs/libraries
- **Medium Guide:** https://medium.com/@thatsiemguy/getting-started-with-the-google-secops-sdk-69effdde5978
- **Python SDK:** https://cloud.google.com/python/docs/reference/securityops/latest

---

## Important Reminders

⚠️ **Fresh TODAY**
- Export TODAY before each analysis
- Don't reuse old rules.json
- Rules change daily

⚠️ **For THIS Customer**
- Each customer needs their own export
- Don't share rules.json between customers
- Different credentials = different rules

⚠️ **With Other Files**
- Export rules.json TODAY
- Export detection_results.csv TODAY
- Export event_results.csv TODAY
- Export log_volume.csv TODAY (optional)
- All from same day

---

**SDK setup complete? Proceed to File 2 (detection_results.csv)** →
