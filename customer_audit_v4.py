#!/usr/bin/env python3
"""
YARAL Rule Comparison Tool
Compares Google SecOps JSON rule export against detection/event CSV data.

This script analyzes:
1. Rules defined in JSON vs rules triggering in SecOps (from detection_results.csv)
2. Event coverage - which events are being detected vs unmapped (from event_results.csv)
3. Log volume context (from log_volume.csv - optional)

Input Files:
- rules.json (or .jq): JSON export of SecOps rules with name, logic, status
- detection_results.csv: Detection triggers from SecOps
- event_results.csv: All events in environment
- log_volume.csv: Weekly log volume (optional)

Output:
- HTML report with comprehensive comparison analysis
"""

import json
import csv
import re
import os
import sys
import webbrowser
from datetime import datetime
from collections import defaultdict
from pathlib import Path

# Try tkinter for file dialogs, fall back to command line
try:
    import tkinter as tk
    from tkinter import filedialog
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False


def select_file(title, filetypes):
    """Open file dialog or prompt for file path."""
    if HAS_TKINTER:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        filepath = filedialog.askopenfilename(title=title, filetypes=filetypes)
        root.destroy()
        return filepath
    else:
        print(f"\n{title}")
        return input("Enter file path: ").strip()


def clean_json_string(json_str):
    """Clean common JSON issues like trailing commas."""
    import re
    
    # Remove trailing commas before } or ]
    cleaned = re.sub(r',\s*}', '}', json_str)
    cleaned = re.sub(r',\s*]', ']', cleaned)
    
    return cleaned


def extract_rules_robustly(filepath):
    """
    Extract rules from JSON file even if some entries are malformed.
    Uses multiple strategies to recover as many rules as possible.
    """
    rules = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        raw_content = f.read()
    
    # Strategy 1: Try standard parsing with cleanup
    cleaned = clean_json_string(raw_content)
    try:
        data = json.loads(cleaned)
        print("  ✓ JSON parsed successfully")
        return data
    except json.JSONDecodeError as e:
        print(f"  ⚠ Standard parsing failed at position {e.pos}: {e.msg}")
    
    # Strategy 2: Split by rule objects and parse individually
    print("  Attempting to extract rules individually...")
    
    # Find all objects that look like rules (have displayName field)
    # Pattern to match individual rule objects
    rule_pattern = r'\{\s*"name"\s*:\s*"projects/[^}]+?"ruleId"\s*:\s*"[^"]+"\s*\}'
    
    # Alternative: Split on rule boundaries
    # Each rule starts with { "name": "projects/
    chunks = re.split(r'(?=\{\s*"name"\s*:\s*"projects/)', cleaned)
    
    successful = 0
    failed = 0
    
    for i, chunk in enumerate(chunks):
        if not chunk.strip() or chunk.strip() == '[' or chunk.strip() == ']':
            continue
            
        # Clean up the chunk
        chunk = chunk.strip()
        
        # Remove leading/trailing commas and brackets from array context
        chunk = re.sub(r'^[\[\],\s]+', '', chunk)
        chunk = re.sub(r'[\[\],\s]+$', '', chunk)
        
        if not chunk.startswith('{'):
            continue
            
        # Ensure it ends with }
        if not chunk.endswith('}'):
            # Try to find the last complete }
            last_brace = chunk.rfind('}')
            if last_brace > 0:
                chunk = chunk[:last_brace + 1]
        
        # Try to parse this chunk
        try:
            rule = json.loads(chunk)
            if isinstance(rule, dict) and ('displayName' in rule or 'name' in rule):
                rules.append(rule)
                successful += 1
        except json.JSONDecodeError:
            # Try to fix common issues in this chunk
            try:
                # Fix unquoted values that might appear
                fixed_chunk = re.sub(r':\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*([,}])', r': "\1"\2', chunk)
                fixed_chunk = clean_json_string(fixed_chunk)
                rule = json.loads(fixed_chunk)
                if isinstance(rule, dict) and ('displayName' in rule or 'name' in rule):
                    rules.append(rule)
                    successful += 1
            except json.JSONDecodeError:
                failed += 1
                if failed <= 3:  # Only show first few failures
                    preview = chunk[:100] + '...' if len(chunk) > 100 else chunk
                    print(f"    ⚠ Could not parse rule chunk {i}: {preview}")
    
    if failed > 3:
        print(f"    ... and {failed - 3} more failed chunks")
    
    print(f"  ✓ Extracted {successful} rules ({failed} malformed entries skipped)")
    return rules


def load_json_rules(filepath):
    """Load rules from JSON/JQ file."""
    rules = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            raw_content = f.read()
        
        # First try standard JSON parsing
        try:
            data = json.loads(raw_content)
            print("  ✓ JSON parsed successfully (no cleanup needed)")
        except json.JSONDecodeError as e:
            print(f"⚠ Standard JSON parsing failed: {e}")
            print("  Attempting to fix common JSON issues...")
            
            # Try cleanup
            cleaned_content = clean_json_string(raw_content)
            try:
                data = json.loads(cleaned_content)
                print("  ✓ Successfully parsed after removing trailing commas")
            except json.JSONDecodeError as e2:
                print(f"  ⚠ Cleanup failed: {e2}")
                print("  Attempting robust extraction (parsing rules individually)...")
                
                # Use robust extraction
                data = extract_rules_robustly(filepath)
                
                if not data:
                    print("  ✗ Could not extract any rules from the file")
                    return []
        
        for rule in data:
            # Extract key fields
            rule_info = {
                'displayName': rule.get('displayName', ''),
                'ruleId': rule.get('ruleId', ''),
                'text': rule.get('text', ''),
                'enabled': rule.get('enabled', False),
                'alerting': rule.get('alerting', False),
                'compilationState': rule.get('compilationState', ''),
                'runFrequency': rule.get('runFrequency', ''),
                'executionState': rule.get('executionState', ''),
                'type': rule.get('type', ''),
                'severity': rule.get('severity', {}).get('displayName', ''),
                'createTime': rule.get('createTime', ''),
                'revisionCreateTime': rule.get('revisionCreateTime', ''),
                'metadata': rule.get('metadata', {}),
            }
            
            # Parse the rule text to extract log_type, event_type, product_event_type
            rule_info['parsed'] = parse_rule_text(rule.get('text', ''))
            rules.append(rule_info)
        
        print(f"✓ Loaded {len(rules)} rules from JSON file")
        return rules
    except Exception as e:
        print(f"✗ Error loading JSON file: {e}")
        return []


def parse_rule_text(rule_text):
    """Parse YARA-L rule text to extract log types, event types, and product event types."""
    parsed = {
        'log_types': set(),
        'event_types': set(),
        'product_event_types': set(),
        'description': '',
        'mitre': '',
        'severity': '',
    }
    
    if not rule_text:
        return parsed
    
    # Extract log_type patterns
    log_type_patterns = [
        r'\.metadata\.log_type\s*=\s*["\']([^"\']+)["\']',
        r'\.log_type\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in log_type_patterns:
        matches = re.findall(pattern, rule_text)
        parsed['log_types'].update(matches)
    
    # Extract event_type patterns
    event_type_patterns = [
        r'\.metadata\.event_type\s*=\s*["\']([^"\']+)["\']',
        r'\.event_type\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in event_type_patterns:
        matches = re.findall(pattern, rule_text)
        parsed['event_types'].update(matches)
    
    # Extract product_event_type patterns
    product_patterns = [
        r'\.metadata\.product_event_type\s*=\s*["\']([^"\']+)["\']',
        r'\.product_event_type\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in product_patterns:
        matches = re.findall(pattern, rule_text)
        parsed['product_event_types'].update(matches)
    
    # Also check for regex patterns
    regex_patterns = [
        r'\.product_event_type\s*=\s*/([^/]+)/',
        r'\.log_type\s*=\s*/([^/]+)/',
    ]
    for pattern in regex_patterns:
        matches = re.findall(pattern, rule_text)
        # Mark regex patterns with prefix
        for m in matches:
            if 'product_event' in pattern:
                parsed['product_event_types'].add(f"regex:{m}")
            elif 'log_type' in pattern:
                parsed['log_types'].add(f"regex:{m}")
    
    # Extract metadata from rule text
    desc_match = re.search(r'description\s*=\s*["\']([^"\']+)["\']', rule_text)
    if desc_match:
        parsed['description'] = desc_match.group(1)
    
    mitre_match = re.search(r'mitre\s*=\s*["\']([^"\']+)["\']', rule_text)
    if mitre_match:
        parsed['mitre'] = mitre_match.group(1)
    
    sev_match = re.search(r'severity\s*=\s*["\']([^"\']+)["\']', rule_text)
    if sev_match:
        parsed['severity'] = sev_match.group(1)
    
    return parsed


def load_detection_csv(filepath):
    """Load detection results CSV."""
    detections = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Try to detect delimiter
            sample = f.read(2048)
            f.seek(0)
            
            if '\t' in sample:
                reader = csv.DictReader(f, delimiter='\t')
            else:
                reader = csv.DictReader(f)
            
            # Normalize column names
            for row in reader:
                normalized = {}
                for key, value in row.items():
                    if key:
                        norm_key = key.lower().strip().replace(' ', '_')
                        normalized[norm_key] = value
                detections.append(normalized)
        
        print(f"✓ Loaded {len(detections)} detection records from CSV")
        return detections
    except Exception as e:
        print(f"✗ Error loading detection CSV: {e}")
        return []


def load_event_csv(filepath):
    """Load event results CSV."""
    events = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            sample = f.read(2048)
            f.seek(0)
            
            if '\t' in sample:
                reader = csv.DictReader(f, delimiter='\t')
            else:
                reader = csv.DictReader(f)
            
            for row in reader:
                normalized = {}
                for key, value in row.items():
                    if key:
                        norm_key = key.lower().strip().replace(' ', '_')
                        normalized[norm_key] = value
                events.append(normalized)
        
        print(f"✓ Loaded {len(events)} event records from CSV")
        return events
    except Exception as e:
        print(f"✗ Error loading event CSV: {e}")
        return []


def load_log_volume_csv(filepath):
    """Load log volume CSV (optional)."""
    if not filepath or not os.path.exists(filepath):
        return []
    
    volumes = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            sample = f.read(2048)
            f.seek(0)
            
            if '\t' in sample:
                reader = csv.DictReader(f, delimiter='\t')
            else:
                reader = csv.DictReader(f)
            
            for row in reader:
                normalized = {}
                for key, value in row.items():
                    if key:
                        norm_key = key.lower().strip().replace(' ', '_')
                        normalized[norm_key] = value
                volumes.append(normalized)
        
        print(f"✓ Loaded {len(volumes)} log volume records from CSV")
        return volumes
    except Exception as e:
        print(f"⚠ Could not load log volume CSV: {e}")
        return []


def analyze_rules(json_rules, detections, events, volumes):
    """Perform comprehensive analysis comparing JSON rules to CSV data."""
    analysis = {
        'summary': {},
        'rule_status': [],
        'rules_in_json_not_triggering': [],
        'rules_triggering_not_in_json': [],
        'event_coverage': {},
        'unmapped_events': [],
        'log_volume_summary': [],
        'mitre_coverage': defaultdict(list),
    }
    
    # Build set of rule names from JSON
    json_rule_names = {r['displayName'] for r in json_rules}
    json_rules_by_name = {r['displayName']: r for r in json_rules}
    
    # Build set of rule names from detections CSV
    detection_rule_names = set()
    detection_by_rule = defaultdict(list)
    
    # Try different column name variations
    rule_name_cols = ['rule_name', 'rulename', 'rule', 'name', '$rule_name']
    
    for det in detections:
        rule_name = None
        for col in rule_name_cols:
            if col in det and det[col]:
                rule_name = det[col]
                break
        
        if rule_name:
            detection_rule_names.add(rule_name)
            detection_by_rule[rule_name].append(det)
    
    # Compare JSON rules vs Detection CSV
    rules_in_both = json_rule_names & detection_rule_names
    rules_only_in_json = json_rule_names - detection_rule_names
    rules_only_in_csv = detection_rule_names - json_rule_names
    
    # Build comprehensive rule status
    for rule in json_rules:
        name = rule['displayName']
        status = {
            'name': name,
            'in_json': True,
            'in_detections': name in detection_rule_names,
            'enabled': rule.get('enabled', False),
            'alerting': rule.get('alerting', False),
            'compilation_state': rule.get('compilationState', ''),
            'run_frequency': rule.get('runFrequency', ''),
            'execution_state': rule.get('executionState', ''),
            'severity': rule.get('severity', ''),
            'type': rule.get('type', ''),
            'mitre': rule.get('metadata', {}).get('mitre', '') or rule['parsed'].get('mitre', ''),
            'description': rule.get('metadata', {}).get('description', '') or rule['parsed'].get('description', ''),
            'log_types': list(rule['parsed'].get('log_types', [])),
            'event_types': list(rule['parsed'].get('event_types', [])),
            'product_event_types': list(rule['parsed'].get('product_event_types', [])),
            'trigger_count': 0,
        }
        
        # Get trigger count from detections
        if name in detection_by_rule:
            for det in detection_by_rule[name]:
                try:
                    count = int(det.get('trigger_count', 0) or det.get('event_count', 0) or 0)
                    status['trigger_count'] += count
                except (ValueError, TypeError):
                    pass
        
        analysis['rule_status'].append(status)
        
        # Track MITRE coverage
        if status['mitre']:
            analysis['mitre_coverage'][status['mitre']].append(name)
    
    # Rules in CSV but not in JSON
    for name in rules_only_in_csv:
        analysis['rules_triggering_not_in_json'].append({
            'name': name,
            'detections': detection_by_rule[name]
        })
    
    # Rules in JSON but not triggering
    analysis['rules_in_json_not_triggering'] = [
        r for r in analysis['rule_status'] 
        if not r['in_detections'] and r['enabled']
    ]
    
    # Build event coverage from events CSV
    event_combinations = set()
    event_details = []
    
    log_type_cols = ['log_type', '$log_type', 'logtype']
    event_type_cols = ['event_type', '$event_type', 'eventtype']
    product_cols = ['product_event_type', '$product_event_type', 'productevent', 'product_event']
    
    for evt in events:
        log_type = None
        event_type = None
        product_event = None
        
        for col in log_type_cols:
            if col in evt and evt[col]:
                log_type = evt[col]
                break
        for col in event_type_cols:
            if col in evt and evt[col]:
                event_type = evt[col]
                break
        for col in product_cols:
            if col in evt and evt[col]:
                product_event = evt[col]
                break
        
        if log_type:
            combo = (log_type, event_type or '', product_event or '')
            event_combinations.add(combo)
            
            event_count = 0
            try:
                event_count = int(evt.get('event_count', 0) or evt.get('$event_count', 0) or 0)
            except (ValueError, TypeError):
                pass
            
            event_details.append({
                'log_type': log_type,
                'event_type': event_type or '',
                'product_event_type': product_event or '',
                'event_count': event_count,
            })
    
    # Determine which events are mapped by rules
    mapped_events = set()
    for rule in json_rules:
        parsed = rule['parsed']
        rule_log_types = parsed.get('log_types', set())
        rule_event_types = parsed.get('event_types', set())
        rule_product_types = parsed.get('product_event_types', set())
        
        for combo in event_combinations:
            log_type, event_type, product_event = combo
            
            # Check if rule covers this event combination
            log_match = (not rule_log_types or 
                        log_type in rule_log_types or
                        any(log_type in lt for lt in rule_log_types if lt.startswith('regex:')))
            
            event_match = (not rule_event_types or 
                         event_type in rule_event_types)
            
            product_match = (not rule_product_types or 
                           product_event in rule_product_types or
                           any(product_event in pt for pt in rule_product_types if pt.startswith('regex:')))
            
            if log_match and event_match and product_match and rule_log_types:
                mapped_events.add(combo)
    
    unmapped_events = event_combinations - mapped_events
    
    # Build unmapped events list with counts
    for evt in event_details:
        combo = (evt['log_type'], evt['event_type'], evt['product_event_type'])
        if combo in unmapped_events:
            analysis['unmapped_events'].append(evt)
    
    # Sort unmapped by event count
    analysis['unmapped_events'].sort(key=lambda x: x['event_count'], reverse=True)
    
    # Process log volumes
    if volumes:
        volume_by_log = defaultdict(lambda: {'event_count': 0, 'gb': 0})
        for vol in volumes:
            log_type = None
            for col in log_type_cols:
                if col in vol and vol[col]:
                    log_type = vol[col]
                    break
            
            if log_type:
                try:
                    count = int(vol.get('event_count', 0) or vol.get('$event_count', 0) or 0)
                    volume_by_log[log_type]['event_count'] += count
                except (ValueError, TypeError):
                    pass
                
                try:
                    gb = float(vol.get('week_gigabytes', 0) or vol.get('$week_gigabytes', 0) or 0)
                    volume_by_log[log_type]['gb'] += gb
                except (ValueError, TypeError):
                    pass
        
        analysis['log_volume_summary'] = [
            {'log_type': lt, **data} 
            for lt, data in sorted(volume_by_log.items(), key=lambda x: x[1]['event_count'], reverse=True)
        ]
    
    # Summary statistics
    total_json_rules = len(json_rules)
    enabled_rules = sum(1 for r in json_rules if r.get('enabled', False))
    alerting_rules = sum(1 for r in json_rules if r.get('alerting', False))
    compiled_rules = sum(1 for r in json_rules if r.get('compilationState') == 'SUCCEEDED')
    
    analysis['summary'] = {
        'total_rules_in_json': total_json_rules,
        'enabled_rules': enabled_rules,
        'alerting_rules': alerting_rules,
        'compiled_rules': compiled_rules,
        'rules_triggering': len(rules_in_both),
        'rules_not_triggering': len(rules_only_in_json),
        'rules_in_csv_not_json': len(rules_only_in_csv),
        'total_event_combinations': len(event_combinations),
        'mapped_events': len(mapped_events),
        'unmapped_events': len(unmapped_events),
        'coverage_percentage': (len(mapped_events) / len(event_combinations) * 100) if event_combinations else 0,
    }
    
    return analysis


def generate_html_report(analysis, json_rules, output_path):
    """Generate comprehensive HTML report."""
    summary = analysis['summary']
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M%p")
    
    # Count rules by status
    enabled_count = sum(1 for r in analysis['rule_status'] if r['enabled'])
    disabled_count = len(analysis['rule_status']) - enabled_count
    
    # Group unmapped events by log type
    unmapped_by_log = defaultdict(list)
    for evt in analysis['unmapped_events']:
        unmapped_by_log[evt['log_type']].append(evt)
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecOps Rule Comparison Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        
        header {{
            background: linear-gradient(135deg, #1a73e8, #0d47a1);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        header h1 {{ font-size: 2rem; margin-bottom: 10px; }}
        header p {{ opacity: 0.9; }}
        .header-meta {{ margin-top: 15px; font-size: 0.9rem; opacity: 0.8; }}
        
        .pdf-btn {{
            background: #dc3545;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            margin-top: 15px;
            transition: background 0.2s;
        }}
        .pdf-btn:hover {{ background: #c82333; }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            text-align: center;
        }}
        .summary-card .value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #1a73e8;
        }}
        .summary-card .label {{
            color: #666;
            font-size: 0.9rem;
            margin-top: 5px;
        }}
        .summary-card.success .value {{ color: #28a745; }}
        .summary-card.warning .value {{ color: #ffc107; }}
        .summary-card.danger .value {{ color: #dc3545; }}
        
        .section {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }}
        .section h2 {{
            color: #1a73e8;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e8f0fe;
        }}
        
        .coverage-bar {{
            background: #e9ecef;
            border-radius: 10px;
            height: 30px;
            overflow: hidden;
            margin: 20px 0;
        }}
        .coverage-fill {{
            background: linear-gradient(90deg, #28a745, #20c997);
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            transition: width 0.5s;
        }}
        
        .table-container {{
            overflow-x: auto;
            margin-top: 15px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
            position: sticky;
            top: 0;
            cursor: pointer;
        }}
        th:hover {{ background: #e9ecef; }}
        th[data-sort-dir="asc"]:after {{
            content: ' ▲';
            font-size: 0.8rem;
        }}
        th[data-sort-dir="desc"]:after {{
            content: ' ▼';
            font-size: 0.8rem;
        }}
        tr:hover {{ background: #f8f9fa; }}
        
        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
        }}
        .status-enabled {{ background: #d4edda; color: #155724; }}
        .status-disabled {{ background: #f8d7da; color: #721c24; }}
        .status-alerting {{ background: #cce5ff; color: #004085; }}
        .status-live {{ background: #d1ecf1; color: #0c5460; }}
        .status-succeeded {{ background: #d4edda; color: #155724; }}
        
        .log-group {{
            margin-bottom: 25px;
        }}
        .log-group h3 {{
            background: #f8f9fa;
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .log-group .count {{
            background: #dc3545;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
        }}
        
        .mitre-tag {{
            display: inline-block;
            background: #6f42c1;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            margin: 2px;
        }}
        
        .rule-logic {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
            max-height: 200px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        
        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}
        .collapsible:after {{
            content: ' ▼';
            font-size: 0.8rem;
        }}
        .collapsible.collapsed:after {{
            content: ' ▶';
        }}
        .collapse-content {{
            display: block;
        }}
        .collapse-content.hidden {{
            display: none;
        }}
        
        @media print {{
            body {{ background: white; }}
            .section {{ box-shadow: none; border: 1px solid #ddd; }}
            .pdf-btn {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 SecOps Rule Comparison Report</h1>
            <p>JSON Rule Export vs Detection/Event Analysis</p>
            <div class="header-meta">
                Generated on {timestamp}
            </div>
            <button class="pdf-btn" onclick="window.print()">📥 Download as PDF</button>
        </header>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="value">{summary['total_rules_in_json']}</div>
                <div class="label">Total Rules in JSON</div>
            </div>
            <div class="summary-card success">
                <div class="value">{summary['enabled_rules']}</div>
                <div class="label">Enabled Rules</div>
            </div>
            <div class="summary-card">
                <div class="value">{summary['alerting_rules']}</div>
                <div class="label">Alerting Rules</div>
            </div>
            <div class="summary-card success">
                <div class="value">{summary['rules_triggering']}</div>
                <div class="label">Rules Triggering</div>
            </div>
            <div class="summary-card warning">
                <div class="value">{summary['rules_not_triggering']}</div>
                <div class="label">Enabled Not Triggering</div>
            </div>
            <div class="summary-card danger">
                <div class="value">{summary['unmapped_events']}</div>
                <div class="label">Unmapped Events</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📈 Detection Coverage Overview</h2>
            <p>Event combinations covered by active detection rules</p>
            <div class="coverage-bar">
                <div class="coverage-fill" style="width: {summary['coverage_percentage']:.1f}%">
                    {summary['coverage_percentage']:.1f}% Covered
                </div>
            </div>
            <p><strong>{summary['mapped_events']}</strong> of <strong>{summary['total_event_combinations']}</strong> event combinations are mapped to detection rules.</p>
        </div>
        
        <div class="section">
            <h2>📋 All Rules from JSON Export</h2>
            <p>Complete list of rules with status and configuration</p>
            <div class="table-container">
                <table class="sortable">
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Status</th>
                            <th>Alerting</th>
                            <th>Frequency</th>
                            <th>Severity</th>
                            <th>MITRE</th>
                            <th>Triggers</th>
                            <th>Log Types</th>
                        </tr>
                    </thead>
                    <tbody>
'''
    
    # Sort rules: enabled first, then by name
    sorted_rules = sorted(analysis['rule_status'], key=lambda x: (not x['enabled'], x['name']))
    
    for rule in sorted_rules:
        enabled_class = 'status-enabled' if rule['enabled'] else 'status-disabled'
        enabled_text = 'Enabled' if rule['enabled'] else 'Disabled'
        alerting_class = 'status-alerting' if rule['alerting'] else ''
        alerting_text = 'Yes' if rule['alerting'] else 'No'
        log_types = ', '.join(rule['log_types'][:3]) or 'N/A'
        if len(rule['log_types']) > 3:
            log_types += f' (+{len(rule["log_types"]) - 3})'
        
        html += f'''
                        <tr>
                            <td><strong>{rule['name']}</strong></td>
                            <td><span class="status-badge {enabled_class}">{enabled_text}</span></td>
                            <td><span class="status-badge {alerting_class}">{alerting_text}</span></td>
                            <td>{rule['run_frequency'] or 'N/A'}</td>
                            <td>{rule['severity'] or 'N/A'}</td>
                            <td>{f'<span class="mitre-tag">{rule["mitre"]}</span>' if rule['mitre'] else 'N/A'}</td>
                            <td>{rule['trigger_count']:,}</td>
                            <td>{log_types}</td>
                        </tr>
'''
    
    html += '''
                    </tbody>
                </table>
            </div>
        </div>
'''
    
    # Rules in JSON but not triggering
    if analysis['rules_in_json_not_triggering']:
        html += '''
        <div class="section">
            <h2>⚠️ Enabled Rules Not Triggering</h2>
            <p>These rules are enabled but haven't generated any detections in the analysis period</p>
            <div class="table-container">
                <table class="sortable">
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Severity</th>
                            <th>MITRE</th>
                            <th>Log Types</th>
                            <th>Event Types</th>
                        </tr>
                    </thead>
                    <tbody>
'''
        for rule in analysis['rules_in_json_not_triggering']:
            log_types = ', '.join(rule['log_types']) or 'N/A'
            event_types = ', '.join(rule['event_types']) or 'N/A'
            html += f'''
                        <tr>
                            <td><strong>{rule['name']}</strong></td>
                            <td>{rule['severity'] or 'N/A'}</td>
                            <td>{rule['mitre'] or 'N/A'}</td>
                            <td>{log_types}</td>
                            <td>{event_types}</td>
                        </tr>
'''
        html += '''
                    </tbody>
                </table>
            </div>
        </div>
'''
    
    # Rules in CSV but not in JSON
    if analysis['rules_triggering_not_in_json']:
        html += '''
        <div class="section">
            <h2>❓ Rules Triggering but Not in JSON Export</h2>
            <p>These rules appear in detection data but weren't found in the JSON file</p>
            <div class="table-container">
                <table class="sortable">
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Detection Count</th>
                        </tr>
                    </thead>
                    <tbody>
'''
        for item in analysis['rules_triggering_not_in_json'][:50]:
            html += f'''
                        <tr>
                            <td><strong>{item['name']}</strong></td>
                            <td>{len(item['detections'])}</td>
                        </tr>
'''
        html += '''
                    </tbody>
                </table>
            </div>
        </div>
'''
    
    # Log Volume Summary
    if analysis['log_volume_summary']:
        max_count = max(v['event_count'] for v in analysis['log_volume_summary']) if analysis['log_volume_summary'] else 1
        html += '''
        <div class="section">
            <h2>📊 Log Volume Summary</h2>
            <div class="table-container">
                <table class="sortable">
                    <thead>
                        <tr>
                            <th>Log Type</th>
                            <th>Event Count</th>
                            <th>Volume (GB)</th>
                            <th>Relative Volume</th>
                        </tr>
                    </thead>
                    <tbody>
'''
        for vol in analysis['log_volume_summary'][:20]:
            pct = (vol['event_count'] / max_count * 100) if max_count else 0
            html += f'''
                        <tr>
                            <td><strong>{vol['log_type']}</strong></td>
                            <td>{vol['event_count']:,}</td>
                            <td>{vol['gb']:.2f}</td>
                            <td>
                                <div class="coverage-bar" style="height: 20px; margin: 0;">
                                    <div class="coverage-fill" style="width: {pct:.1f}%; background: #1a73e8;"></div>
                                </div>
                            </td>
                        </tr>
'''
        html += '''
                    </tbody>
                </table>
            </div>
        </div>
'''
    
    # Unmapped Events by Log Type
    if unmapped_by_log:
        html += '''
        <div class="section">
            <h2>🔍 Unmapped Event Combinations</h2>
            <p>Events occurring in your environment without detection rule coverage</p>
'''
        for log_type, events in sorted(unmapped_by_log.items()):
            html += f'''
            <div class="log-group">
                <h3 class="collapsible" onclick="this.classList.toggle('collapsed'); this.nextElementSibling.classList.toggle('hidden');">
                    {log_type}
                    <span class="count">{len(events)} unmapped</span>
                </h3>
                <div class="collapse-content">
                    <table class="sortable">
                        <thead>
                            <tr>
                                <th>Event Type</th>
                                <th>Product Event Type</th>
                                <th>Event Count</th>
                            </tr>
                        </thead>
                        <tbody>
'''
            for evt in sorted(events, key=lambda x: x['event_count'], reverse=True)[:25]:
                html += f'''
                            <tr>
                                <td>{evt['event_type'] or 'N/A'}</td>
                                <td>{evt['product_event_type'] or 'N/A'}</td>
                                <td>{evt['event_count']:,}</td>
                            </tr>
'''
            if len(events) > 25:
                html += f'''
                            <tr>
                                <td colspan="3" style="text-align: center; color: #666;">
                                    ... and {len(events) - 25} more unmapped events
                                </td>
                            </tr>
'''
            html += '''
                        </tbody>
                    </table>
                </div>
            </div>
'''
        html += '''
        </div>
'''
    
    # MITRE Coverage
    if analysis['mitre_coverage']:
        html += '''
        <div class="section">
            <h2>🎯 MITRE ATT&CK Coverage</h2>
            <p>Rules mapped to MITRE techniques</p>
            <div class="table-container">
                <table class="sortable">
                    <thead>
                        <tr>
                            <th>MITRE Technique</th>
                            <th>Rule Count</th>
                            <th>Rules</th>
                        </tr>
                    </thead>
                    <tbody>
'''
        for mitre, rules in sorted(analysis['mitre_coverage'].items()):
            rule_names = ', '.join(rules[:5])
            if len(rules) > 5:
                rule_names += f' (+{len(rules) - 5} more)'
            html += f'''
                        <tr>
                            <td><span class="mitre-tag">{mitre}</span></td>
                            <td>{len(rules)}</td>
                            <td>{rule_names}</td>
                        </tr>
'''
        html += '''
                    </tbody>
                </table>
            </div>
        </div>
'''
    
    html += '''
    </div>
    
    <script>
        function getCellValue(cell) {
            if (!cell) return '';
            let text = cell.innerText.trim().replace(/,/g, '');
            let num = parseFloat(text);
            return isNaN(num) ? text.toLowerCase() : num;
        }

        function sortTable(table, col) {
            const thead = table.querySelector('thead');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.rows);

            // Determine sort direction
            const currentDir = thead.rows[0].cells[col].getAttribute('data-sort-dir') || 'asc';
            const newDir = currentDir === 'asc' ? 'desc' : 'asc';

            // Sort rows
            rows.sort((rowA, rowB) => {
                const valA = getCellValue(rowA.cells[col]);
                const valB = getCellValue(rowB.cells[col]);

                if (valA === valB) return 0;

                if (newDir === 'asc') {
                    return (valA > valB ? 1 : -1);
                } else {
                    return (valA < valB ? 1 : -1);
                }
            });

            // Clear existing rows
            while (tbody.firstChild) {
                tbody.removeChild(tbody.firstChild);
            }

            // Append sorted rows
            rows.forEach(row => tbody.appendChild(row));

            // Update direction
            Array.from(thead.rows[0].cells).forEach(cell => cell.removeAttribute('data-sort-dir'));
            thead.rows[0].cells[col].setAttribute('data-sort-dir', newDir);
        }

        // Initialize all collapsibles as expanded
        document.querySelectorAll('.collapsible').forEach(el => {
            // Start expanded
        });

        // Add click handlers to th in sortable tables
        document.querySelectorAll('table.sortable th').forEach((th, col) => {
            th.onclick = () => sortTable(th.closest('table'), col);
        });
    </script>
</body>
</html>
'''
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return output_path


def main():
    print("=" * 80)
    print("  SecOps Rule Comparison Tool")
    print("  Compare JSON Rule Export vs Detection/Event CSV Data")
    print("=" * 80)
    print()
    
    # Select JSON rules file - accepts any filename
    print("Step 1: Select your JSON rules file")
    print("        (Customer rule exports - any .json or .jq file)")
    json_path = select_file(
        "Select Customer JSON Rules File (any filename)",
        [("JSON files", "*.json *.jq"), ("All files", "*.*")]
    )
    if not json_path:
        print("No JSON file selected. Exiting.")
        return
    
    # Select detection CSV
    print("\nStep 2: Select detection_results.csv")
    detection_path = select_file(
        "Select Detection Results CSV",
        [("CSV files", "*.csv"), ("All files", "*.*")]
    )
    if not detection_path:
        print("No detection CSV selected. Exiting.")
        return
    
    # Select event CSV
    print("\nStep 3: Select event_results.csv")
    event_path = select_file(
        "Select Event Results CSV",
        [("CSV files", "*.csv"), ("All files", "*.*")]
    )
    if not event_path:
        print("No event CSV selected. Exiting.")
        return
    
    # Select log volume CSV (optional)
    print("\nStep 4: Select log_volume.csv (optional - Cancel to skip)")
    volume_path = select_file(
        "Select Log Volume CSV (Optional)",
        [("CSV files", "*.csv"), ("All files", "*.*")]
    )
    
    print("\n" + "-" * 80)
    print("Loading files...")
    print("-" * 80)
    
    # Load all data
    json_rules = load_json_rules(json_path)
    if not json_rules:
        print("Failed to load JSON rules. Exiting.")
        return
    
    detections = load_detection_csv(detection_path)
    events = load_event_csv(event_path)
    volumes = load_log_volume_csv(volume_path) if volume_path else []
    
    print("\n" + "-" * 80)
    print("Analyzing data...")
    print("-" * 80)
    
    # Perform analysis
    analysis = analyze_rules(json_rules, detections, events, volumes)
    
    # Print summary
    print(f"\n📊 Analysis Summary:")
    print(f"   Total rules in JSON: {analysis['summary']['total_rules_in_json']}")
    print(f"   Enabled rules: {analysis['summary']['enabled_rules']}")
    print(f"   Rules triggering: {analysis['summary']['rules_triggering']}")
    print(f"   Enabled but not triggering: {len(analysis['rules_in_json_not_triggering'])}")
    print(f"   Event coverage: {analysis['summary']['coverage_percentage']:.1f}%")
    print(f"   Unmapped events: {analysis['summary']['unmapped_events']}")
    
    # Generate report
    print("\n" + "-" * 80)
    print("Generating HTML report...")
    print("-" * 80)
    
    output_path = os.path.join(os.path.expanduser("~"), "Downloads", "rule_comparison_report.html")
    generate_html_report(analysis, json_rules, output_path)
    
    print(f"\n✓ Report saved to: {output_path}")
    
    # Open in browser
    try:
        webbrowser.open(f"file://{output_path}")
        print("✓ Report opened in browser")
    except Exception as e:
        print(f"Could not open browser: {e}")
        print(f"Please open the file manually: {output_path}")
    
    print("\n" + "=" * 80)
    print("Done!")
    print("=" * 80)


if __name__ == "__main__":
    main()
