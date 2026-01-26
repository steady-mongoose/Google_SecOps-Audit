#!/usr/bin/env python3
"""
YARAL Rule Comparison Tool v8
Compares Google SecOps JSON rule export against detection/event CSV data.

CHANGES IN V8:
- Added search box for filtering rules by name
- Added dropdown filters for Status, Specificity, Severity, Log Type
- Improved column sorting with visual indicators
- Added row count display
- Export filtered results capability

Input Files:
- rules.json (or .jq): JSON export of SecOps rules
- detection_results.csv: Detection triggers from SecOps
- event_results.csv: All events in environment
- log_volume.csv: Weekly log volume (optional)

Output:
- HTML report with filtering, searching, and sorting
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

try:
    import tkinter as tk
    from tkinter import filedialog
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False


def select_file(title, filetypes):
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
    cleaned = re.sub(r',\s*}', '}', json_str)
    cleaned = re.sub(r',\s*]', ']', cleaned)
    return cleaned


def extract_rules_robustly(filepath):
    rules = []
    with open(filepath, 'r', encoding='utf-8') as f:
        raw_content = f.read()
    
    cleaned = clean_json_string(raw_content)
    try:
        data = json.loads(cleaned)
        print("  [OK] JSON parsed successfully")
        return data
    except json.JSONDecodeError as e:
        print(f"  [!] Standard parsing failed: {e.msg}")
    
    print("  Attempting individual extraction...")
    chunks = re.split(r'(?=\{\s*"name"\s*:\s*"projects/)', cleaned)
    
    successful = 0
    for chunk in chunks:
        chunk = chunk.strip()
        chunk = re.sub(r'^[\[\],\s]+', '', chunk)
        chunk = re.sub(r'[\[\],\s]+$', '', chunk)
        if not chunk.startswith('{'):
            continue
        if not chunk.endswith('}'):
            last_brace = chunk.rfind('}')
            if last_brace > 0:
                chunk = chunk[:last_brace + 1]
        try:
            rule = json.loads(chunk)
            if isinstance(rule, dict) and ('displayName' in rule or 'name' in rule):
                rules.append(rule)
                successful += 1
        except json.JSONDecodeError:
            pass
    
    print(f"  [OK] Extracted {successful} rules")
    return rules


def load_json_rules(filepath):
    rules = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            raw_content = f.read()
        
        try:
            data = json.loads(raw_content)
            print("  [OK] JSON parsed successfully")
        except json.JSONDecodeError:
            cleaned_content = clean_json_string(raw_content)
            try:
                data = json.loads(cleaned_content)
                print("  [OK] Parsed after cleanup")
            except json.JSONDecodeError:
                data = extract_rules_robustly(filepath)
                if not data:
                    return []
        
        for rule in data:
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
            rule_info['parsed'] = parse_rule_text(rule.get('text', ''))
            rules.append(rule_info)
        
        print(f"[OK] Loaded {len(rules)} rules")
        return rules
    except Exception as e:
        print(f"[X] Error: {e}")
        return []


def parse_rule_text(rule_text):
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
    
    log_patterns = [
        r'\.metadata\.log_type\s*=\s*["\']([^"\']+)["\']',
        r'\.log_type\s*=\s*["\']([^"\']+)["\']',
        r'\$[a-zA-Z_][a-zA-Z0-9_]*\.metadata\.log_type\s*=\s*["\']([^"\']+)["\']',
        r'\.metadata\.product_name\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in log_patterns:
        matches = re.findall(pattern, rule_text, re.IGNORECASE)
        parsed['log_types'].update([m.upper() for m in matches])
    
    event_patterns = [
        r'\.metadata\.event_type\s*=\s*["\']([^"\']+)["\']',
        r'\.event_type\s*=\s*["\']([^"\']+)["\']',
        r'\$[a-zA-Z_][a-zA-Z0-9_]*\.metadata\.event_type\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in event_patterns:
        matches = re.findall(pattern, rule_text, re.IGNORECASE)
        parsed['event_types'].update([m.upper() for m in matches])
    
    product_patterns = [
        r'\.metadata\.product_event_type\s*=\s*["\']([^"\']+)["\']',
        r'\.product_event_type\s*=\s*["\']([^"\']+)["\']',
        r'\$[a-zA-Z_][a-zA-Z0-9_]*\.metadata\.product_event_type\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in product_patterns:
        matches = re.findall(pattern, rule_text, re.IGNORECASE)
        parsed['product_event_types'].update([m.upper() for m in matches])
    
    for pattern in [r'\.log_type\s*=\s*/([^/]+)/', r'\.metadata\.log_type\s*=\s*/([^/]+)/']:
        for m in re.findall(pattern, rule_text):
            parsed['log_types'].add(f"regex:{m}")
    
    for pattern in [r'\.product_event_type\s*=\s*/([^/]+)/']:
        for m in re.findall(pattern, rule_text):
            parsed['product_event_types'].add(f"regex:{m}")
    
    desc_match = re.search(r'description\s*=\s*["\']([^"\']+)["\']', rule_text)
    if desc_match:
        parsed['description'] = desc_match.group(1)
    
    mitre_match = re.search(r'mitre\s*=\s*["\']([^"\']+)["\']', rule_text)
    if mitre_match:
        parsed['mitre'] = mitre_match.group(1)
    
    return parsed


def load_detection_csv(filepath):
    detections = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            sample = f.read(2048)
            f.seek(0)
            delimiter = '\t' if '\t' in sample else ','
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                normalized = {k.lower().strip().replace(' ', '_'): v for k, v in row.items() if k}
                detections.append(normalized)
        print(f"[OK] Loaded {len(detections)} detections")
        return detections
    except Exception as e:
        print(f"[X] Error: {e}")
        return []


def load_event_csv(filepath):
    events = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            sample = f.read(2048)
            f.seek(0)
            delimiter = '\t' if '\t' in sample else ','
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                normalized = {k.lower().strip().replace(' ', '_'): v for k, v in row.items() if k}
                events.append(normalized)
        print(f"[OK] Loaded {len(events)} events")
        return events
    except Exception as e:
        print(f"[X] Error: {e}")
        return []


def load_log_volume_csv(filepath):
    if not filepath or not os.path.exists(filepath):
        return [], [], None, None, 0, {}
    
    raw_volumes = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            sample = f.read(2048)
            f.seek(0)
            delimiter = '\t' if '\t' in sample else ','
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                normalized = {k.lower().strip().replace(' ', '_'): v for k, v in row.items() if k}
                
                try:
                    normalized['event_count'] = int(str(normalized.get('event_count', 0)).replace(',', ''))
                except:
                    normalized['event_count'] = 0
                
                normalized['gb'] = 0.0
                for col in ['week_gigabytes', 'gb', 'gigabytes']:
                    if col in normalized and normalized[col]:
                        try:
                            normalized['gb'] = float(str(normalized[col]).replace(',', ''))
                            break
                        except:
                            pass
                
                normalized['week_date'] = normalized.get('week', normalized.get('day', normalized.get('date', '')))
                raw_volumes.append(normalized)
        
        date_parsed = []
        for vol in raw_volumes:
            if vol['week_date']:
                for fmt in ['%Y-%m-%d', '%Y/%m/%d', '%m/%d/%Y']:
                    try:
                        vol['week_date_parsed'] = datetime.strptime(vol['week_date'], fmt)
                        date_parsed.append(vol['week_date_parsed'])
                        break
                    except:
                        continue
        
        unique_weeks = sorted(set(date_parsed))
        num_weeks = len(unique_weeks)
        week_to_num = {w: i + 1 for i, w in enumerate(unique_weeks)}
        
        for vol in raw_volumes:
            vol['week_num'] = week_to_num.get(vol.get('week_date_parsed'), 0)
        
        min_date = unique_weeks[0] if unique_weeks else None
        max_date = unique_weeks[-1] if unique_weeks else None
        
        weekly_by_log = defaultdict(lambda: defaultdict(lambda: {'event_count': 0, 'gb': 0.0}))
        for vol in raw_volumes:
            log_type = (vol.get('log_type', '') or '').upper()
            if log_type and vol.get('week_num', 0) > 0:
                weekly_by_log[log_type][vol['week_num']]['event_count'] += vol['event_count']
                weekly_by_log[log_type][vol['week_num']]['gb'] += vol['gb']
        
        weekly_volumes = []
        for log_type, weeks in weekly_by_log.items():
            total_events = sum(w['event_count'] for w in weeks.values())
            total_gb = sum(w['gb'] for w in weeks.values())
            week_data = {f'week_{i}_gb': weeks.get(i, {}).get('gb', 0.0) for i in range(1, num_weeks + 1)}
            weekly_volumes.append({'log_type': log_type, 'total_events': total_events, 'total_gb': total_gb, **week_data})
        weekly_volumes.sort(key=lambda x: x['total_gb'], reverse=True)
        
        aggregated = [{'log_type': lt, 'event_count': sum(w['event_count'] for w in wks.values()), 
                       'gb': sum(w['gb'] for w in wks.values())} for lt, wks in weekly_by_log.items()]
        aggregated.sort(key=lambda x: x['gb'], reverse=True)
        
        week_labels = {i + 1: w.strftime('%d %b') for i, w in enumerate(unique_weeks)}
        
        print(f"[OK] Loaded {len(aggregated)} log types across {num_weeks} weeks")
        return aggregated, weekly_volumes, min_date, max_date, num_weeks, week_labels
    except Exception as e:
        print(f"[!] Error: {e}")
        return [], [], None, None, 0, {}


def match_string(value, pattern):
    if not value or not pattern:
        return False
    value = value.upper().strip()
    pattern = pattern.upper().strip()
    if pattern.startswith('REGEX:'):
        try:
            return bool(re.search(pattern[6:], value, re.IGNORECASE))
        except:
            return False
    return value == pattern


def analyze_rules(json_rules, detections, events, volumes, weekly_volumes, date_range, num_weeks, week_labels):
    analysis = {
        'summary': {},
        'rule_status': [],
        'rules_in_json_not_triggering': [],
        'rules_triggering_not_in_json': [],
        'coverage_details': [],
        'unmapped_events': [],
        'log_volume_summary': volumes,
        'weekly_volumes': weekly_volumes,
        'mitre_coverage': defaultdict(list),
        'date_range': date_range,
        'num_weeks': num_weeks,
        'week_labels': week_labels,
    }
    
    json_rule_names = {r['displayName'] for r in json_rules}
    detection_rule_names = set()
    detection_by_rule = defaultdict(list)
    
    for det in detections:
        rule_name = det.get('rule_name') or det.get('rulename') or det.get('name', '')
        if rule_name:
            detection_rule_names.add(rule_name)
            detection_by_rule[rule_name].append(det)
    
    rules_in_both = json_rule_names & detection_rule_names
    
    for rule in json_rules:
        name = rule['displayName']
        has_log = len(rule['parsed']['log_types']) > 0
        has_event = len(rule['parsed']['event_types']) > 0
        has_product = len(rule['parsed']['product_event_types']) > 0
        
        if has_log and has_event and has_product:
            specificity = 'exact'
        elif has_log and (has_event or has_product):
            specificity = 'partial'
        elif has_log:
            specificity = 'broad'
        else:
            specificity = 'none'
        
        trigger_count = 0
        if name in detection_by_rule:
            for det in detection_by_rule[name]:
                try:
                    trigger_count += int(det.get('trigger_count', 0) or det.get('event_count', 0) or 0)
                except:
                    pass
        
        status = {
            'name': name,
            'enabled': rule.get('enabled', False),
            'alerting': rule.get('alerting', False),
            'in_detections': name in detection_rule_names,
            'run_frequency': rule.get('runFrequency', ''),
            'severity': rule.get('severity', '') or 'N/A',
            'mitre': rule.get('metadata', {}).get('mitre', '') or rule['parsed'].get('mitre', ''),
            'log_types': sorted(list(rule['parsed']['log_types'])),
            'event_types': sorted(list(rule['parsed']['event_types'])),
            'product_event_types': sorted(list(rule['parsed']['product_event_types'])),
            'specificity': specificity,
            'trigger_count': trigger_count,
        }
        analysis['rule_status'].append(status)
        
        if status['mitre']:
            analysis['mitre_coverage'][status['mitre']].append(name)
    
    analysis['rules_in_json_not_triggering'] = [r for r in analysis['rule_status'] if not r['in_detections'] and r['enabled']]
    
    for name in (detection_rule_names - json_rule_names):
        analysis['rules_triggering_not_in_json'].append({'name': name, 'detections': detection_by_rule[name]})
    
    event_details = []
    for evt in events:
        log_type = (evt.get('log_type') or evt.get('$log_type') or '').upper().strip()
        event_type = (evt.get('event_type') or evt.get('$event_type') or '').upper().strip()
        product_event = (evt.get('product_event_type') or evt.get('$product_event_type') or '').upper().strip()
        if log_type:
            try:
                event_count = int(str(evt.get('event_count', 0)).replace(',', ''))
            except:
                event_count = 0
            event_details.append({'log_type': log_type, 'event_type': event_type, 'product_event_type': product_event, 'event_count': event_count})
    
    exact_matches, partial_matches, broad_matches, unmapped_events = [], [], [], []
    enabled_rules = [r for r in json_rules if r.get('enabled', False)]
    
    for evt in event_details:
        best_match = 'unmapped'
        matching_rules = []
        
        for rule in enabled_rules:
            parsed = rule['parsed']
            if not parsed['log_types']:
                continue
            
            if not any(match_string(evt['log_type'], p) for p in parsed['log_types']):
                continue
            
            event_match = any(match_string(evt['event_type'], p) for p in parsed['event_types']) if parsed['event_types'] else None
            product_match = any(match_string(evt['product_event_type'], p) for p in parsed['product_event_types']) if parsed['product_event_types'] else None
            
            if event_match is not None and product_match is not None:
                if event_match and product_match:
                    best_match = 'exact'
                    matching_rules = [rule['displayName']]
            elif event_match is not None or product_match is not None:
                if (event_match if event_match is not None else product_match):
                    if best_match not in ['exact', 'partial']:
                        best_match = 'partial'
                        matching_rules = [rule['displayName']]
            else:
                if best_match == 'unmapped':
                    best_match = 'broad'
                    matching_rules = [rule['displayName']]
        
        evt_record = {**evt, 'coverage_level': best_match, 'matching_rules': matching_rules[:5], 'num_matching_rules': len(matching_rules)}
        
        if best_match == 'exact':
            exact_matches.append(evt_record)
        elif best_match == 'partial':
            partial_matches.append(evt_record)
        elif best_match == 'broad':
            broad_matches.append(evt_record)
        else:
            unmapped_events.append(evt_record)
    
    total = len(event_details)
    analysis['coverage_details'] = {'exact_matches': exact_matches, 'partial_matches': partial_matches, 'broad_matches': broad_matches, 'unmapped_events': unmapped_events}
    analysis['unmapped_events'] = unmapped_events
    analysis['summary'] = {
        'total_rules_in_json': len(json_rules),
        'enabled_rules': sum(1 for r in json_rules if r.get('enabled', False)),
        'alerting_rules': sum(1 for r in json_rules if r.get('alerting', False)),
        'rules_triggering': len(rules_in_both),
        'rules_not_triggering': len(analysis['rules_in_json_not_triggering']),
        'total_event_combinations': total,
        'exact_matches': len(exact_matches),
        'partial_matches': len(partial_matches),
        'broad_matches': len(broad_matches),
        'unmapped_events': len(unmapped_events),
        'conservative_coverage_pct': ((len(exact_matches) + len(partial_matches)) / total * 100) if total else 0,
        'rules_with_exact_spec': sum(1 for r in analysis['rule_status'] if r['specificity'] == 'exact'),
        'rules_with_partial_spec': sum(1 for r in analysis['rule_status'] if r['specificity'] == 'partial'),
        'rules_with_broad_spec': sum(1 for r in analysis['rule_status'] if r['specificity'] == 'broad'),
        'rules_with_no_spec': sum(1 for r in analysis['rule_status'] if r['specificity'] == 'none'),
    }
    
    return analysis


def generate_html_report(analysis, json_rules, output_path):
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M%p")
    summary = analysis['summary']
    
    unmapped_by_log = defaultdict(list)
    for evt in analysis['unmapped_events']:
        unmapped_by_log[evt['log_type'] or 'UNKNOWN'].append(evt)
    
    all_severities = sorted(set(r['severity'] for r in analysis['rule_status'] if r['severity'] and r['severity'] != 'N/A'))
    all_log_types = sorted(set(lt for r in analysis['rule_status'] for lt in r['log_types']))
    
    date_range_str = ""
    if analysis.get('date_range') and analysis['date_range'][0] and analysis['date_range'][1]:
        min_date, max_date = analysis['date_range']
        date_range_str = f"{min_date.strftime('%d %b %Y')} - {max_date.strftime('%d %b %Y')}"
    
    num_weeks = analysis.get('num_weeks', 0)
    week_labels = analysis.get('week_labels', {})
    
    # Build severity options
    sev_options = '\n'.join(f'<option value="{s}">{s}</option>' for s in all_severities)
    log_options = '\n'.join(f'<option value="{lt}">{lt}</option>' for lt in all_log_types[:50])
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecOps Rule Comparison Report v8</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 1600px; margin: 0 auto; padding: 20px; }}
        
        header {{
            background: linear-gradient(135deg, #1a73e8, #0d47a1);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        header h1 {{ font-size: 2rem; margin-bottom: 10px; }}
        .header-meta {{ margin-top: 15px; font-size: 0.9rem; opacity: 0.8; }}
        
        .btn {{
            background: #dc3545;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            margin: 5px;
            transition: background 0.2s;
        }}
        .btn:hover {{ background: #c82333; }}
        .btn.secondary {{ background: #6c757d; }}
        .btn.secondary:hover {{ background: #5a6268; }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            text-align: center;
        }}
        .summary-card .value {{ font-size: 2rem; font-weight: 700; color: #1a73e8; }}
        .summary-card .label {{ color: #666; font-size: 0.85rem; margin-top: 5px; }}
        .summary-card.success .value {{ color: #28a745; }}
        .summary-card.warning .value {{ color: #ffc107; }}
        .summary-card.danger .value {{ color: #dc3545; }}
        .summary-card.info .value {{ color: #17a2b8; }}
        
        .section {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }}
        .section h2 {{
            color: #1a73e8;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e8f0fe;
        }}
        
        /* Filter Controls */
        .filter-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
            margin-bottom: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 5px;
        }}
        .filter-group label {{
            font-size: 0.8rem;
            font-weight: 600;
            color: #495057;
        }}
        .filter-group input, .filter-group select {{
            padding: 8px 12px;
            border: 1px solid #ced4da;
            border-radius: 6px;
            font-size: 0.9rem;
            min-width: 150px;
        }}
        .filter-group input:focus, .filter-group select:focus {{
            outline: none;
            border-color: #1a73e8;
            box-shadow: 0 0 0 3px rgba(26,115,232,0.1);
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
        }}
        .search-box input {{
            width: 100%;
            padding: 10px 15px;
            font-size: 1rem;
        }}
        .filter-stats {{
            font-size: 0.9rem;
            color: #666;
            padding: 10px 0;
        }}
        .clear-filters {{
            background: #e9ecef;
            color: #495057;
            border: none;
            padding: 8px 15px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
        }}
        .clear-filters:hover {{ background: #dee2e6; }}
        
        /* Coverage */
        .coverage-stacked {{
            display: flex;
            height: 30px;
            border-radius: 10px;
            overflow: hidden;
            margin: 15px 0;
        }}
        .coverage-stacked > div {{
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 0.8rem;
            min-width: 40px;
        }}
        .coverage-legend {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin: 15px 0;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 4px;
        }}
        
        /* Tables */
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
            user-select: none;
            white-space: nowrap;
        }}
        th:hover {{ background: #e9ecef; }}
        th .sort-icon {{ margin-left: 5px; opacity: 0.3; }}
        th.sorted-asc .sort-icon, th.sorted-desc .sort-icon {{ opacity: 1; }}
        th.sorted-asc .sort-icon::after {{ content: '▲'; }}
        th.sorted-desc .sort-icon::after {{ content: '▼'; }}
        th:not(.sorted-asc):not(.sorted-desc) .sort-icon::after {{ content: '⇅'; }}
        tr:hover {{ background: #f8f9fa; }}
        tr.hidden {{ display: none; }}
        
        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
        }}
        .status-enabled {{ background: #d4edda; color: #155724; }}
        .status-disabled {{ background: #f8d7da; color: #721c24; }}
        .status-exact {{ background: #d4edda; color: #155724; }}
        .status-partial {{ background: #d1ecf1; color: #0c5460; }}
        .status-broad {{ background: #fff3cd; color: #856404; }}
        .status-none {{ background: #f8d7da; color: #721c24; }}
        
        .log-tag {{
            display: inline-block;
            background: #e8f0fe;
            color: #174ea6;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            margin: 2px;
        }}
        .mitre-tag {{
            display: inline-block;
            background: #6f42c1;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
        }}
        
        .log-group {{
            margin-bottom: 20px;
        }}
        .log-group h3 {{
            background: #f8f9fa;
            padding: 12px 15px;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
        }}
        .log-group .count {{
            background: #dc3545;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
        }}
        .collapse-content.hidden {{ display: none; }}
        
        .info-box {{
            background: #e8f4fd;
            border-left: 4px solid #1a73e8;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }}
        .info-box.warning {{ background: #fff3cd; border-left-color: #ffc107; }}
        
        .gb-cell {{ text-align: right; font-family: 'Courier New', monospace; }}
        
        @media print {{
            .filter-bar, .btn {{ display: none !important; }}
            .section {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SecOps Rule Comparison Report</h1>
            <p>JSON Rule Export vs Detection/Event Analysis (v8 - With Filtering)</p>
            <div class="header-meta">
                Generated on {timestamp}
                {f'<br>Data Period: {date_range_str} ({num_weeks} weeks)' if date_range_str else ''}
            </div>
            <button class="btn" onclick="window.print()">Download as PDF</button>
            <button class="btn secondary" onclick="exportToCSV()">Export Rules CSV</button>
        </header>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="value">{summary['total_rules_in_json']}</div>
                <div class="label">Total Rules</div>
            </div>
            <div class="summary-card success">
                <div class="value">{summary['enabled_rules']}</div>
                <div class="label">Enabled</div>
            </div>
            <div class="summary-card">
                <div class="value">{summary['rules_triggering']}</div>
                <div class="label">Triggering</div>
            </div>
            <div class="summary-card warning">
                <div class="value">{summary['rules_not_triggering']}</div>
                <div class="label">Not Triggering</div>
            </div>
            <div class="summary-card info">
                <div class="value">{summary['total_event_combinations']}</div>
                <div class="label">Event Types</div>
            </div>
            <div class="summary-card danger">
                <div class="value">{summary['unmapped_events']}</div>
                <div class="label">Unmapped</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Detection Coverage Overview</h2>
            <div class="coverage-stacked">
                <div style="width: {summary['exact_matches'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%; background: #28a745;">{summary['exact_matches']}</div>
                <div style="width: {summary['partial_matches'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%; background: #17a2b8;">{summary['partial_matches']}</div>
                <div style="width: {summary['broad_matches'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%; background: #ffc107; color: #333;">{summary['broad_matches']}</div>
                <div style="width: {summary['unmapped_events'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%; background: #dc3545;">{summary['unmapped_events']}</div>
            </div>
            <div class="coverage-legend">
                <div class="legend-item"><div class="legend-color" style="background: #28a745;"></div><span><strong>Exact ({summary['exact_matches']})</strong></span></div>
                <div class="legend-item"><div class="legend-color" style="background: #17a2b8;"></div><span><strong>Partial ({summary['partial_matches']})</strong></span></div>
                <div class="legend-item"><div class="legend-color" style="background: #ffc107;"></div><span><strong>Broad ({summary['broad_matches']})</strong></span></div>
                <div class="legend-item"><div class="legend-color" style="background: #dc3545;"></div><span><strong>Unmapped ({summary['unmapped_events']})</strong></span></div>
            </div>
            <div class="info-box">
                <strong>Accurate Coverage: {summary['conservative_coverage_pct']:.1f}%</strong> (Exact + Partial only)
            </div>
        </div>
'''
    
    # Weekly Log Volume
    if analysis.get('weekly_volumes') and num_weeks > 0:
        html += f'''
        <div class="section">
            <h2>Log Volume by Week (GB)</h2>
            <div class="table-container">
                <table class="sortable" id="volumeTable">
                    <thead><tr>
                        <th onclick="sortTable('volumeTable', 0)">Log Type <span class="sort-icon"></span></th>
                        <th onclick="sortTable('volumeTable', 1)">Total (GB) <span class="sort-icon"></span></th>
'''
        for w in range(1, min(num_weeks + 1, 7)):
            html += f'<th onclick="sortTable(\'volumeTable\', {w+1})">Wk {w}<br><small>{week_labels.get(w, "")}</small> <span class="sort-icon"></span></th>'
        html += '</tr></thead><tbody>'
        
        for vol in analysis['weekly_volumes'][:20]:
            html += f'<tr><td><strong>{vol["log_type"]}</strong></td><td class="gb-cell">{vol["total_gb"]:.2f}</td>'
            for w in range(1, min(num_weeks + 1, 7)):
                html += f'<td class="gb-cell">{vol.get(f"week_{w}_gb", 0):.2f}</td>'
            html += '</tr>'
        html += '</tbody></table></div></div>'
    
    # Rules Table with Filters
    html += f'''
        <div class="section">
            <h2>All Rules from JSON Export</h2>
            
            <div class="filter-bar">
                <div class="filter-group search-box">
                    <label>Search Rules</label>
                    <input type="text" id="searchInput" placeholder="Type to search rule names..." onkeyup="filterTable()">
                </div>
                <div class="filter-group">
                    <label>Status</label>
                    <select id="statusFilter" onchange="filterTable()">
                        <option value="">All</option>
                        <option value="Enabled">Enabled</option>
                        <option value="Disabled">Disabled</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Specificity</label>
                    <select id="specFilter" onchange="filterTable()">
                        <option value="">All</option>
                        <option value="exact">Exact</option>
                        <option value="partial">Partial</option>
                        <option value="broad">Broad</option>
                        <option value="none">None</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Severity</label>
                    <select id="severityFilter" onchange="filterTable()">
                        <option value="">All</option>
                        {sev_options}
                    </select>
                </div>
                <div class="filter-group">
                    <label>Log Type</label>
                    <select id="logTypeFilter" onchange="filterTable()">
                        <option value="">All</option>
                        {log_options}
                    </select>
                </div>
                <button class="clear-filters" onclick="clearFilters()">Clear Filters</button>
            </div>
            
            <div class="filter-stats">
                Showing <span id="visibleCount">{len(analysis['rule_status'])}</span> of {len(analysis['rule_status'])} rules
            </div>
            
            <div class="table-container">
                <table class="sortable" id="rulesTable">
                    <thead>
                        <tr>
                            <th onclick="sortTable('rulesTable', 0)">Rule Name <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 1)">Status <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 2)">Specificity <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 3)">Severity <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 4)">MITRE <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 5)">Triggers <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 6)">Log Types <span class="sort-icon"></span></th>
                        </tr>
                    </thead>
                    <tbody>
'''
    
    sorted_rules = sorted(analysis['rule_status'], key=lambda x: (not x['enabled'], x['name']))
    for rule in sorted_rules:
        enabled_class = 'status-enabled' if rule['enabled'] else 'status-disabled'
        enabled_text = 'Enabled' if rule['enabled'] else 'Disabled'
        spec_class = f"status-{rule['specificity']}"
        spec_text = rule['specificity'].title()
        
        log_types_str = ' '.join(rule['log_types']) if rule['log_types'] else ''
        log_display = ''.join(f'<span class="log-tag">{lt}</span>' for lt in rule['log_types'][:3])
        if len(rule['log_types']) > 3:
            log_display += f' +{len(rule["log_types"])-3}'
        if not log_display:
            log_display = '<em style="color:#999">None</em>'
        
        html += f'''                        <tr data-name="{rule['name'].lower()}" data-status="{enabled_text}" data-spec="{rule['specificity']}" data-severity="{rule['severity']}" data-logtypes="{log_types_str.lower()}">
                            <td><strong>{rule['name']}</strong></td>
                            <td><span class="status-badge {enabled_class}">{enabled_text}</span></td>
                            <td><span class="status-badge {spec_class}">{spec_text}</span></td>
                            <td>{rule['severity']}</td>
                            <td>{f'<span class="mitre-tag">{rule["mitre"]}</span>' if rule['mitre'] else 'N/A'}</td>
                            <td>{rule['trigger_count']:,}</td>
                            <td>{log_display}</td>
                        </tr>
'''
    
    html += '''                    </tbody>
                </table>
            </div>
        </div>
'''
    
    # Unmapped Events
    if unmapped_by_log:
        html += '''
        <div class="section">
            <h2>Unmapped Event Combinations</h2>
'''
        for log_type in sorted(unmapped_by_log.keys()):
            evts = unmapped_by_log[log_type]
            html += f'''
            <div class="log-group">
                <h3 onclick="this.nextElementSibling.classList.toggle('hidden')">
                    {log_type} <span class="count">{len(evts)} unmapped</span>
                </h3>
                <div class="collapse-content">
                    <table><thead><tr><th>Event Type</th><th>Product Event</th><th>Count</th></tr></thead><tbody>
'''
            for evt in sorted(evts, key=lambda x: x['event_count'], reverse=True)[:20]:
                html += f'<tr><td>{evt["event_type"] or "N/A"}</td><td>{evt["product_event_type"] or "N/A"}</td><td>{evt["event_count"]:,}</td></tr>'
            html += '</tbody></table></div></div>'
        html += '</div>'
    
    # JavaScript
    html += '''
    </div>
    <script>
        function filterTable() {
            const search = document.getElementById('searchInput').value.toLowerCase();
            const status = document.getElementById('statusFilter').value;
            const spec = document.getElementById('specFilter').value;
            const severity = document.getElementById('severityFilter').value;
            const logType = document.getElementById('logTypeFilter').value.toLowerCase();
            
            const rows = document.querySelectorAll('#rulesTable tbody tr');
            let visible = 0;
            
            rows.forEach(row => {
                const name = row.dataset.name || '';
                const rowStatus = row.dataset.status || '';
                const rowSpec = row.dataset.spec || '';
                const rowSeverity = row.dataset.severity || '';
                const rowLogTypes = row.dataset.logtypes || '';
                
                const matchSearch = !search || name.includes(search);
                const matchStatus = !status || rowStatus === status;
                const matchSpec = !spec || rowSpec === spec;
                const matchSeverity = !severity || rowSeverity === severity;
                const matchLogType = !logType || rowLogTypes.includes(logType);
                
                if (matchSearch && matchStatus && matchSpec && matchSeverity && matchLogType) {
                    row.classList.remove('hidden');
                    visible++;
                } else {
                    row.classList.add('hidden');
                }
            });
            
            document.getElementById('visibleCount').textContent = visible;
        }
        
        function clearFilters() {
            document.getElementById('searchInput').value = '';
            document.getElementById('statusFilter').value = '';
            document.getElementById('specFilter').value = '';
            document.getElementById('severityFilter').value = '';
            document.getElementById('logTypeFilter').value = '';
            filterTable();
        }
        
        function sortTable(tableId, colIndex) {
            const table = document.getElementById(tableId);
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const th = table.querySelectorAll('th')[colIndex];
            
            // Determine sort direction
            const isAsc = !th.classList.contains('sorted-asc');
            
            // Clear other sort indicators
            table.querySelectorAll('th').forEach(header => {
                header.classList.remove('sorted-asc', 'sorted-desc');
            });
            
            th.classList.add(isAsc ? 'sorted-asc' : 'sorted-desc');
            
            rows.sort((a, b) => {
                let aVal = a.cells[colIndex]?.textContent.trim().replace(/,/g, '') || '';
                let bVal = b.cells[colIndex]?.textContent.trim().replace(/,/g, '') || '';
                
                const aNum = parseFloat(aVal);
                const bNum = parseFloat(bVal);
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return isAsc ? aNum - bNum : bNum - aNum;
                }
                return isAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }
        
        function exportToCSV() {
            const rows = document.querySelectorAll('#rulesTable tbody tr:not(.hidden)');
            let csv = 'Rule Name,Status,Specificity,Severity,MITRE,Triggers,Log Types\\n';
            
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                const rowData = Array.from(cells).map(cell => {
                    let text = cell.textContent.trim().replace(/"/g, '""');
                    return `"${text}"`;
                });
                csv += rowData.join(',') + '\\n';
            });
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'rules_export.csv';
            a.click();
            window.URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>
'''
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return output_path


def main():
    print("=" * 70)
    print("  SecOps Rule Comparison Tool v8")
    print("  With Filtering, Searching, and Sorting")
    print("=" * 70)
    
    print("\nStep 1: Select JSON rules file")
    json_path = select_file("Select JSON Rules", [("JSON", "*.json *.jq"), ("All", "*.*")])
    if not json_path:
        return
    
    print("\nStep 2: Select detection_results.csv")
    det_path = select_file("Select Detections CSV", [("CSV", "*.csv"), ("All", "*.*")])
    if not det_path:
        return
    
    print("\nStep 3: Select event_results.csv")
    evt_path = select_file("Select Events CSV", [("CSV", "*.csv"), ("All", "*.*")])
    if not evt_path:
        return
    
    print("\nStep 4: Select log_volume.csv (Cancel to skip)")
    vol_path = select_file("Select Volume CSV", [("CSV", "*.csv"), ("All", "*.*")])
    
    print("\n" + "-" * 70)
    print("Loading...")
    
    json_rules = load_json_rules(json_path)
    if not json_rules:
        return
    
    detections = load_detection_csv(det_path)
    events = load_event_csv(evt_path)
    
    if vol_path:
        volumes, weekly, min_d, max_d, num_w, labels = load_log_volume_csv(vol_path)
    else:
        volumes, weekly, min_d, max_d, num_w, labels = [], [], None, None, 0, {}
    
    print("\nAnalyzing...")
    analysis = analyze_rules(json_rules, detections, events, volumes, weekly, (min_d, max_d), num_w, labels)
    
    print(f"\n  Summary:")
    print(f"  - Rules: {analysis['summary']['total_rules_in_json']} ({analysis['summary']['enabled_rules']} enabled)")
    print(f"  - Coverage: {analysis['summary']['conservative_coverage_pct']:.1f}%")
    print(f"  - Unmapped: {analysis['summary']['unmapped_events']}")
    
    output_path = os.path.join(os.path.expanduser("~"), "Downloads", "rule_comparison_report.html")
    generate_html_report(analysis, json_rules, output_path)
    
    print(f"\n[OK] Saved: {output_path}")
    
    try:
        webbrowser.open(f"file://{output_path}")
    except:
        pass
    
    print("\nDone!")


if __name__ == "__main__":
    main()
