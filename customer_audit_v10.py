#!/usr/bin/env python3
"""
YARAL Rule Comparison Tool v10
Compares Google SecOps JSON rule export against detection/event CSV data.

CHANGES IN V10:
- Enhanced YARA-L parsing (OR conditions, regex expansion, multi-event rules)
- Dynamic condition detection with flags
- Rule quality scoring (0-100)
- Rule age analysis (stale rule detection)
- Improved coverage accuracy metrics
- Chronicle API integration option (placeholder)

Input Files:
- rules.json (or .jq): JSON export of SecOps rules
- detection_results.csv: Detection triggers from SecOps
- event_results.csv: All events in environment
- log_volume.csv: Weekly log volume (optional)

Output:
- HTML report with comprehensive analysis and quality metrics
"""

import json
import csv
import re
import os
import sys
import webbrowser
from datetime import datetime, timedelta
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
            rule_info['parsed'] = parse_rule_text_enhanced(rule.get('text', ''))
            rule_info['dynamic_flags'] = detect_dynamic_conditions(rule.get('text', ''))
            rules.append(rule_info)
        
        print(f"[OK] Loaded {len(rules)} rules")
        return rules
    except Exception as e:
        print(f"[X] Error: {e}")
        import traceback
        traceback.print_exc()
        return []


def parse_rule_text_enhanced(rule_text):
    """Enhanced YARA-L parser with support for OR, regex, multi-event, and negation."""
    parsed = {
        'log_types': set(),
        'event_types': set(),
        'product_event_types': set(),
        'log_types_negated': set(),
        'event_types_negated': set(),
        'product_event_types_negated': set(),
        'regex_patterns': [],
        'multi_event_vars': set(),
        'description': '',
        'mitre': '',
        'severity': '',
        'parsing_confidence': 'high',
        'parsing_notes': [],
    }
    
    if not rule_text:
        return parsed
    
    # =========================================================================
    # 1. STANDARD EXTRACTION - Direct matches
    # =========================================================================
    
    # Log type - standard patterns
    log_patterns = [
        r'\.metadata\.log_type\s*=\s*["\']([^"\']+)["\']',
        r'\.log_type\s*=\s*["\']([^"\']+)["\']',
        r'\$[a-zA-Z_][a-zA-Z0-9_]*\.metadata\.log_type\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in log_patterns:
        matches = re.findall(pattern, rule_text, re.IGNORECASE)
        parsed['log_types'].update([m.upper() for m in matches])
    
    # Product name as log type
    product_name_patterns = [
        r'\.metadata\.product_name\s*=\s*["\']([^"\']+)["\']',
        r'\.product_name\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in product_name_patterns:
        matches = re.findall(pattern, rule_text, re.IGNORECASE)
        parsed['log_types'].update([m.upper() for m in matches])
    
    # Event type - standard patterns
    event_patterns = [
        r'\.metadata\.event_type\s*=\s*["\']([^"\']+)["\']',
        r'\.event_type\s*=\s*["\']([^"\']+)["\']',
        r'\$[a-zA-Z_][a-zA-Z0-9_]*\.metadata\.event_type\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in event_patterns:
        matches = re.findall(pattern, rule_text, re.IGNORECASE)
        parsed['event_types'].update([m.upper() for m in matches])
    
    # Product event type - standard patterns
    product_patterns = [
        r'\.metadata\.product_event_type\s*=\s*["\']([^"\']+)["\']',
        r'\.product_event_type\s*=\s*["\']([^"\']+)["\']',
        r'\$[a-zA-Z_][a-zA-Z0-9_]*\.metadata\.product_event_type\s*=\s*["\']([^"\']+)["\']',
    ]
    for pattern in product_patterns:
        matches = re.findall(pattern, rule_text, re.IGNORECASE)
        parsed['product_event_types'].update([m.upper() for m in matches])
    
    # =========================================================================
    # 2. OR CONDITIONS - Extract multiple values
    # =========================================================================
    
    # Pattern: log_type = "A" or log_type = "B" or log_type = "C"
    or_log_pattern = r'log_type\s*=\s*["\']([^"\']+)["\']\s*(?:or|\|\|)'
    or_matches = re.findall(or_log_pattern, rule_text, re.IGNORECASE)
    parsed['log_types'].update([m.upper() for m in or_matches])
    
    # Pattern: log_type in ["A", "B", "C"]
    in_log_pattern = r'log_type\s+in\s*\[([^\]]+)\]'
    in_matches = re.findall(in_log_pattern, rule_text, re.IGNORECASE)
    for match in in_matches:
        values = re.findall(r'["\']([^"\']+)["\']', match)
        parsed['log_types'].update([v.upper() for v in values])
    
    # Same for event_type
    or_event_pattern = r'event_type\s*=\s*["\']([^"\']+)["\']\s*(?:or|\|\|)'
    or_matches = re.findall(or_event_pattern, rule_text, re.IGNORECASE)
    parsed['event_types'].update([m.upper() for m in or_matches])
    
    in_event_pattern = r'event_type\s+in\s*\[([^\]]+)\]'
    in_matches = re.findall(in_event_pattern, rule_text, re.IGNORECASE)
    for match in in_matches:
        values = re.findall(r'["\']([^"\']+)["\']', match)
        parsed['event_types'].update([v.upper() for v in values])
    
    # Same for product_event_type
    or_product_pattern = r'product_event_type\s*=\s*["\']([^"\']+)["\']\s*(?:or|\|\|)'
    or_matches = re.findall(or_product_pattern, rule_text, re.IGNORECASE)
    parsed['product_event_types'].update([m.upper() for m in or_matches])
    
    in_product_pattern = r'product_event_type\s+in\s*\[([^\]]+)\]'
    in_matches = re.findall(in_product_pattern, rule_text, re.IGNORECASE)
    for match in in_matches:
        values = re.findall(r'["\']([^"\']+)["\']', match)
        parsed['product_event_types'].update([v.upper() for v in values])
    
    # =========================================================================
    # 3. REGEX PATTERNS - Flag and attempt expansion
    # =========================================================================
    
    regex_log_patterns = [
        r'\.log_type\s*=\s*/([^/]+)/',
        r'\.metadata\.log_type\s*=\s*/([^/]+)/',
        r'\.log_type\s*=~\s*/([^/]+)/',
    ]
    for pattern in regex_log_patterns:
        matches = re.findall(pattern, rule_text)
        for m in matches:
            parsed['regex_patterns'].append(('log_type', m))
            parsed['log_types'].add(f"REGEX:{m}")
            parsed['parsing_notes'].append(f"Regex log_type: /{m}/")
    
    regex_event_patterns = [
        r'\.event_type\s*=\s*/([^/]+)/',
        r'\.metadata\.event_type\s*=\s*/([^/]+)/',
    ]
    for pattern in regex_event_patterns:
        matches = re.findall(pattern, rule_text)
        for m in matches:
            parsed['regex_patterns'].append(('event_type', m))
            parsed['event_types'].add(f"REGEX:{m}")
            parsed['parsing_notes'].append(f"Regex event_type: /{m}/")
    
    regex_product_patterns = [
        r'\.product_event_type\s*=\s*/([^/]+)/',
        r'\.metadata\.product_event_type\s*=\s*/([^/]+)/',
    ]
    for pattern in regex_product_patterns:
        matches = re.findall(pattern, rule_text)
        for m in matches:
            parsed['regex_patterns'].append(('product_event_type', m))
            parsed['product_event_types'].add(f"REGEX:{m}")
            parsed['parsing_notes'].append(f"Regex product_event_type: /{m}/")
    
    # =========================================================================
    # 4. NEGATION - Track what's excluded
    # =========================================================================
    
    neg_log_pattern = r'not\s+.*?\.log_type\s*=\s*["\']([^"\']+)["\']'
    neg_matches = re.findall(neg_log_pattern, rule_text, re.IGNORECASE)
    parsed['log_types_negated'].update([m.upper() for m in neg_matches])
    
    neg_event_pattern = r'not\s+.*?\.event_type\s*=\s*["\']([^"\']+)["\']'
    neg_matches = re.findall(neg_event_pattern, rule_text, re.IGNORECASE)
    parsed['event_types_negated'].update([m.upper() for m in neg_matches])
    
    # != operator
    neq_log_pattern = r'\.log_type\s*!=\s*["\']([^"\']+)["\']'
    neq_matches = re.findall(neq_log_pattern, rule_text, re.IGNORECASE)
    parsed['log_types_negated'].update([m.upper() for m in neq_matches])
    
    # =========================================================================
    # 5. MULTI-EVENT RULES - Track event variables
    # =========================================================================
    
    event_vars = re.findall(r'\$([a-zA-Z][a-zA-Z0-9_]*)\s*\.', rule_text)
    unique_vars = set(event_vars)
    if len(unique_vars) > 1:
        parsed['multi_event_vars'] = unique_vars
        parsed['parsing_notes'].append(f"Multi-event rule with {len(unique_vars)} event variables")
    
    # =========================================================================
    # 6. METADATA EXTRACTION
    # =========================================================================
    
    desc_match = re.search(r'description\s*=\s*["\']([^"\']+)["\']', rule_text)
    if desc_match:
        parsed['description'] = desc_match.group(1)
    
    mitre_match = re.search(r'mitre\s*=\s*["\']([^"\']+)["\']', rule_text)
    if mitre_match:
        parsed['mitre'] = mitre_match.group(1)
    
    sev_match = re.search(r'severity\s*=\s*["\']([^"\']+)["\']', rule_text)
    if sev_match:
        parsed['severity'] = sev_match.group(1)
    
    # =========================================================================
    # 7. CONFIDENCE SCORING
    # =========================================================================
    
    if parsed['regex_patterns']:
        parsed['parsing_confidence'] = 'medium'
    if parsed['multi_event_vars']:
        parsed['parsing_confidence'] = 'medium'
    if not parsed['log_types'] and not parsed['event_types']:
        parsed['parsing_confidence'] = 'low'
    
    return parsed


def detect_dynamic_conditions(rule_text):
    """Detect conditions that can't be statically analyzed."""
    if not rule_text:
        return {}
    
    dynamic_indicators = {
        'reference_list': {
            'pattern': r'%[a-zA-Z_][a-zA-Z0-9_]*',
            'description': 'Uses reference list',
            'severity': 'medium',
        },
        'entity_graph': {
            'pattern': r'\.graph\.',
            'description': 'Uses entity graph context',
            'severity': 'high',
        },
        'prevalence': {
            'pattern': r'prevalence\s*\(',
            'description': 'Uses prevalence function',
            'severity': 'high',
        },
        'risk_score': {
            'pattern': r'\.risk_score\s*[<>=]',
            'description': 'Uses risk score filtering',
            'severity': 'medium',
        },
        'time_window': {
            'pattern': r'over\s+\d+[mhd]',
            'description': 'Uses time-based correlation',
            'severity': 'low',
        },
        'arrays_any': {
            'pattern': r'arrays\.contains|any\s+\$',
            'description': 'Uses array operations',
            'severity': 'low',
        },
        'strings_functions': {
            'pattern': r'strings\.(coalesce|concat|to_lower|to_upper)',
            'description': 'Uses string functions',
            'severity': 'low',
        },
        'net_functions': {
            'pattern': r'net\.(ip_in_range|is_internal)',
            'description': 'Uses network functions',
            'severity': 'low',
        },
        'math_functions': {
            'pattern': r'math\.(abs|log|pow)',
            'description': 'Uses math functions',
            'severity': 'low',
        },
        'outcome_aggregation': {
            'pattern': r'(count|sum|max|min|array_distinct)\s*\(',
            'description': 'Uses outcome aggregation',
            'severity': 'low',
        },
    }
    
    flags = {}
    for name, info in dynamic_indicators.items():
        matches = re.findall(info['pattern'], rule_text, re.IGNORECASE)
        if matches:
            flags[name] = {
                'count': len(matches),
                'description': info['description'],
                'severity': info['severity'],
                'examples': matches[:3],
            }
    
    return flags


def parse_iso_datetime(dt_str):
    """Parse ISO datetime string."""
    if not dt_str:
        return None
    try:
        # Handle various ISO formats
        dt_str = dt_str.replace('Z', '+00:00')
        if '.' in dt_str:
            # Truncate microseconds if too long
            parts = dt_str.split('.')
            if len(parts) == 2:
                frac_and_tz = parts[1]
                if '+' in frac_and_tz:
                    frac, tz = frac_and_tz.split('+')
                    frac = frac[:6]
                    dt_str = f"{parts[0]}.{frac}+{tz}"
                elif '-' in frac_and_tz and len(frac_and_tz) > 6:
                    idx = frac_and_tz.rfind('-')
                    frac = frac_and_tz[:6]
                    tz = frac_and_tz[idx:]
                    dt_str = f"{parts[0]}.{frac}{tz}"
        
        # Try parsing
        for fmt in [
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
        ]:
            try:
                return datetime.strptime(dt_str.split('+')[0].split('Z')[0], fmt.replace('%z', ''))
            except ValueError:
                continue
        return None
    except Exception:
        return None


def calculate_rule_quality(rule, trigger_count, all_log_types_in_env):
    """Calculate rule quality score (0-100)."""
    score = 0
    max_score = 100
    breakdown = {}
    
    # 1. SPECIFICITY (0-25 points)
    specificity = rule.get('specificity', 'none')
    if specificity == 'exact':
        breakdown['specificity'] = 25
    elif specificity == 'partial':
        breakdown['specificity'] = 18
    elif specificity == 'broad':
        breakdown['specificity'] = 8
    else:
        breakdown['specificity'] = 0
    score += breakdown['specificity']
    
    # 2. ACTUALLY TRIGGERING (0-25 points)
    if trigger_count > 100:
        breakdown['triggering'] = 25
    elif trigger_count > 10:
        breakdown['triggering'] = 20
    elif trigger_count > 0:
        breakdown['triggering'] = 15
    elif rule.get('enabled', False):
        breakdown['triggering'] = 0  # Enabled but never triggers
    else:
        breakdown['triggering'] = 5  # Disabled, can't judge
    score += breakdown['triggering']
    
    # 3. HAS MITRE MAPPING (0-15 points)
    mitre = rule.get('mitre', '')
    if mitre and mitre != 'N/A' and len(mitre) > 2:
        if ',' in mitre or len(re.findall(r'T\d{4}', mitre)) > 1:
            breakdown['mitre'] = 15  # Multiple techniques
        else:
            breakdown['mitre'] = 12
    else:
        breakdown['mitre'] = 0
    score += breakdown['mitre']
    
    # 4. HAS DESCRIPTION (0-10 points)
    desc = rule.get('description', '') or rule.get('metadata', {}).get('description', '')
    if desc and len(desc) > 50:
        breakdown['description'] = 10
    elif desc and len(desc) > 10:
        breakdown['description'] = 5
    else:
        breakdown['description'] = 0
    score += breakdown['description']
    
    # 5. RULE FRESHNESS (0-15 points)
    revision_date = parse_iso_datetime(rule.get('revisionCreateTime', ''))
    if revision_date:
        days_old = (datetime.now() - revision_date).days
        if days_old < 90:
            breakdown['freshness'] = 15
        elif days_old < 180:
            breakdown['freshness'] = 12
        elif days_old < 365:
            breakdown['freshness'] = 8
        else:
            breakdown['freshness'] = 3
    else:
        breakdown['freshness'] = 5  # Can't determine
    score += breakdown['freshness']
    
    # 6. TARGETS LOGS IN ENVIRONMENT (0-10 points)
    rule_log_types = set(lt for lt in rule.get('log_types', []) if not lt.startswith('REGEX:'))
    if rule_log_types:
        matching = rule_log_types & all_log_types_in_env
        if matching:
            breakdown['relevance'] = 10
        else:
            breakdown['relevance'] = 2  # Targets logs not in this environment
    else:
        breakdown['relevance'] = 5  # No specific log type
    score += breakdown['relevance']
    
    return {
        'score': min(score, 100),
        'breakdown': breakdown,
        'grade': 'A' if score >= 80 else 'B' if score >= 60 else 'C' if score >= 40 else 'D' if score >= 20 else 'F'
    }


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


def match_string_enhanced(value, pattern):
    """Enhanced matching with regex support."""
    if not value or not pattern:
        return False
    value = value.upper().strip()
    pattern = pattern.upper().strip()
    
    if pattern.startswith('REGEX:'):
        regex_pat = pattern[6:]
        try:
            return bool(re.search(regex_pat, value, re.IGNORECASE))
        except re.error:
            return False
    else:
        return value == pattern


def analyze_rules(json_rules, detections, events, volumes, weekly_volumes, date_range, num_weeks, week_labels):
    analysis = {
        'summary': {},
        'rule_status': [],
        'rules_in_json_not_triggering': [],
        'rules_triggering_not_in_json': [],
        'coverage_details': {},
        'unmapped_events': [],
        'log_volume_summary': volumes,
        'weekly_volumes': weekly_volumes,
        'mitre_coverage': defaultdict(list),
        'date_range': date_range,
        'num_weeks': num_weeks,
        'week_labels': week_labels,
        'quality_summary': {},
        'dynamic_analysis': {},
        'stale_rules': [],
    }
    
    # Get all log types in environment
    all_log_types_in_env = set()
    for evt in events:
        lt = (evt.get('log_type') or evt.get('$log_type') or '').upper().strip()
        if lt:
            all_log_types_in_env.add(lt)
    
    json_rule_names = {r['displayName'] for r in json_rules}
    detection_rule_names = set()
    detection_by_rule = defaultdict(list)
    
    for det in detections:
        rule_name = det.get('rule_name') or det.get('rulename') or det.get('name', '')
        if rule_name:
            detection_rule_names.add(rule_name)
            detection_by_rule[rule_name].append(det)
    
    rules_in_both = json_rule_names & detection_rule_names
    
    # Process each rule
    quality_scores = []
    dynamic_rule_count = 0
    rules_by_confidence = {'high': 0, 'medium': 0, 'low': 0}
    
    for rule in json_rules:
        name = rule['displayName']
        parsed = rule['parsed']
        dynamic_flags = rule['dynamic_flags']
        
        has_log = len([lt for lt in parsed['log_types'] if not lt.startswith('REGEX:')]) > 0 or len([lt for lt in parsed['log_types'] if lt.startswith('REGEX:')]) > 0
        has_event = len(parsed['event_types']) > 0
        has_product = len(parsed['product_event_types']) > 0
        
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
        
        # Calculate quality score
        quality = calculate_rule_quality({
            'specificity': specificity,
            'enabled': rule.get('enabled', False),
            'mitre': rule.get('metadata', {}).get('mitre', '') or parsed.get('mitre', ''),
            'description': parsed.get('description', ''),
            'metadata': rule.get('metadata', {}),
            'revisionCreateTime': rule.get('revisionCreateTime', ''),
            'log_types': list(parsed['log_types']),
        }, trigger_count, all_log_types_in_env)
        
        quality_scores.append(quality['score'])
        
        # Check for stale rules
        revision_date = parse_iso_datetime(rule.get('revisionCreateTime', ''))
        is_stale = False
        days_since_update = None
        if revision_date:
            days_since_update = (datetime.now() - revision_date).days
            if days_since_update > 365:
                is_stale = True
        
        # Track dynamic rules
        if dynamic_flags:
            dynamic_rule_count += 1
        
        # Track parsing confidence
        rules_by_confidence[parsed['parsing_confidence']] += 1
        
        status = {
            'name': name,
            'enabled': rule.get('enabled', False),
            'alerting': rule.get('alerting', False),
            'in_detections': name in detection_rule_names,
            'run_frequency': rule.get('runFrequency', ''),
            'severity': rule.get('severity', '') or 'N/A',
            'mitre': rule.get('metadata', {}).get('mitre', '') or parsed.get('mitre', ''),
            'description': parsed.get('description', ''),
            'log_types': sorted(list(parsed['log_types'])),
            'event_types': sorted(list(parsed['event_types'])),
            'product_event_types': sorted(list(parsed['product_event_types'])),
            'specificity': specificity,
            'trigger_count': trigger_count,
            'quality_score': quality['score'],
            'quality_grade': quality['grade'],
            'quality_breakdown': quality['breakdown'],
            'dynamic_flags': dynamic_flags,
            'parsing_confidence': parsed['parsing_confidence'],
            'parsing_notes': parsed['parsing_notes'],
            'is_stale': is_stale,
            'days_since_update': days_since_update,
            'is_multi_event': len(parsed['multi_event_vars']) > 1,
            'has_regex': len(parsed['regex_patterns']) > 0,
        }
        analysis['rule_status'].append(status)
        
        if is_stale and rule.get('enabled', False):
            analysis['stale_rules'].append(status)
        
        if status['mitre']:
            analysis['mitre_coverage'][status['mitre']].append(name)
    
    analysis['rules_in_json_not_triggering'] = [r for r in analysis['rule_status'] if not r['in_detections'] and r['enabled']]
    
    for name in (detection_rule_names - json_rule_names):
        analysis['rules_triggering_not_in_json'].append({'name': name, 'detections': detection_by_rule[name]})
    
    # Event analysis
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
            
            # Check log type match (including regex)
            log_match = any(match_string_enhanced(evt['log_type'], p) for p in parsed['log_types'])
            if not log_match:
                continue
            
            event_match = any(match_string_enhanced(evt['event_type'], p) for p in parsed['event_types']) if parsed['event_types'] else None
            product_match = any(match_string_enhanced(evt['product_event_type'], p) for p in parsed['product_event_types']) if parsed['product_event_types'] else None
            
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
    analysis['coverage_details'] = {
        'exact_matches': exact_matches,
        'partial_matches': partial_matches,
        'broad_matches': broad_matches,
        'unmapped_events': unmapped_events,
    }
    analysis['unmapped_events'] = unmapped_events
    
    # Quality summary
    avg_quality = sum(quality_scores) / len(quality_scores) if quality_scores else 0
    analysis['quality_summary'] = {
        'average_score': avg_quality,
        'grade_distribution': {
            'A': sum(1 for r in analysis['rule_status'] if r['quality_grade'] == 'A'),
            'B': sum(1 for r in analysis['rule_status'] if r['quality_grade'] == 'B'),
            'C': sum(1 for r in analysis['rule_status'] if r['quality_grade'] == 'C'),
            'D': sum(1 for r in analysis['rule_status'] if r['quality_grade'] == 'D'),
            'F': sum(1 for r in analysis['rule_status'] if r['quality_grade'] == 'F'),
        }
    }
    
    # Dynamic analysis summary
    analysis['dynamic_analysis'] = {
        'total_dynamic_rules': dynamic_rule_count,
        'parsing_confidence': rules_by_confidence,
        'rules_with_reference_lists': sum(1 for r in analysis['rule_status'] if 'reference_list' in r['dynamic_flags']),
        'rules_with_entity_graph': sum(1 for r in analysis['rule_status'] if 'entity_graph' in r['dynamic_flags']),
        'rules_with_prevalence': sum(1 for r in analysis['rule_status'] if 'prevalence' in r['dynamic_flags']),
        'multi_event_rules': sum(1 for r in analysis['rule_status'] if r['is_multi_event']),
        'regex_rules': sum(1 for r in analysis['rule_status'] if r['has_regex']),
    }
    
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
        'stale_rules_count': len(analysis['stale_rules']),
        'dynamic_rules_count': dynamic_rule_count,
        'average_quality_score': avg_quality,
    }
    
    return analysis


def generate_html_report(analysis, json_rules, output_path):
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M%p")
    summary = analysis['summary']
    quality_summary = analysis['quality_summary']
    dynamic_analysis = analysis['dynamic_analysis']
    
    unmapped_by_log = defaultdict(list)
    for evt in analysis['unmapped_events']:
        unmapped_by_log[evt['log_type'] or 'UNKNOWN'].append(evt)
    
    all_severities = sorted(set(r['severity'] for r in analysis['rule_status'] if r['severity'] and r['severity'] != 'N/A'))
    all_log_types = sorted(set(lt for r in analysis['rule_status'] for lt in r['log_types'] if not lt.startswith('REGEX:')))
    
    date_range_str = ""
    if analysis.get('date_range') and analysis['date_range'][0] and analysis['date_range'][1]:
        min_date, max_date = analysis['date_range']
        date_range_str = f"{min_date.strftime('%d %b %Y')} - {max_date.strftime('%d %b %Y')}"
    
    num_weeks = analysis.get('num_weeks', 0)
    week_labels = analysis.get('week_labels', {})
    
    sev_options = '\n'.join(f'<option value="{s}">{s}</option>' for s in all_severities)
    log_options = '\n'.join(f'<option value="{lt}">{lt}</option>' for lt in all_log_types[:50])
    
    # Get unique event types and product event types
    all_event_types = sorted(set(et for r in analysis['rule_status'] for et in r['event_types'] if not et.startswith('REGEX:')))
    all_product_types = sorted(set(pt for r in analysis['rule_status'] for pt in r['product_event_types'] if not pt.startswith('REGEX:')))
    
    event_options = '\n'.join(f'<option value="{et}">{et}</option>' for et in all_event_types[:50])
    product_options = '\n'.join(f'<option value="{pt}">{pt[:40]}</option>' for pt in all_product_types[:50])
    
    # Quality color helper
    def quality_color(score):
        if score >= 80:
            return '#28a745'
        elif score >= 60:
            return '#17a2b8'
        elif score >= 40:
            return '#ffc107'
        else:
            return '#dc3545'
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecOps Rule Comparison Report v10</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
            font-size: 14px;
        }}
        .container {{ max-width: 1800px; margin: 0 auto; padding: 20px; }}
        
        header {{
            background: linear-gradient(135deg, #1a73e8, #0d47a1);
            color: white;
            padding: 25px 30px;
            border-radius: 12px;
            margin-bottom: 25px;
        }}
        header h1 {{ font-size: 1.8rem; margin-bottom: 8px; }}
        .header-meta {{ margin-top: 12px; font-size: 0.85rem; opacity: 0.85; }}
        
        .btn {{
            background: #dc3545;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            margin: 3px;
        }}
        .btn:hover {{ background: #c82333; }}
        .btn.secondary {{ background: #6c757d; }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 12px;
            margin-bottom: 25px;
        }}
        .summary-card {{
            background: white;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            text-align: center;
        }}
        .summary-card .value {{ font-size: 1.6rem; font-weight: 700; color: #1a73e8; }}
        .summary-card .label {{ color: #666; font-size: 0.75rem; margin-top: 4px; }}
        .summary-card.success .value {{ color: #28a745; }}
        .summary-card.warning .value {{ color: #ffc107; }}
        .summary-card.danger .value {{ color: #dc3545; }}
        .summary-card.info .value {{ color: #17a2b8; }}
        
        .section {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}
        .section h2 {{
            color: #1a73e8;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 2px solid #e8f0fe;
            font-size: 1.2rem;
        }}
        .section h3 {{
            color: #495057;
            margin: 18px 0 10px 0;
            font-size: 1rem;
        }}
        
        .metrics-row {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin: 15px 0;
        }}
        .metric-box {{
            flex: 1;
            min-width: 200px;
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }}
        .metric-box .big-number {{
            font-size: 2.5rem;
            font-weight: 700;
        }}
        .metric-box .metric-label {{
            font-size: 0.85rem;
            color: #666;
            margin-top: 5px;
        }}
        
        .quality-bar {{
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 5px 0;
        }}
        .quality-fill {{
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s;
        }}
        
        .grade-badge {{
            display: inline-block;
            width: 28px;
            height: 28px;
            line-height: 28px;
            text-align: center;
            border-radius: 50%;
            font-weight: 700;
            font-size: 0.85rem;
            color: white;
        }}
        .grade-A {{ background: #28a745; }}
        .grade-B {{ background: #17a2b8; }}
        .grade-C {{ background: #ffc107; color: #333; }}
        .grade-D {{ background: #fd7e14; }}
        .grade-F {{ background: #dc3545; }}
        
        .flag-tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            margin: 1px;
            background: #e9ecef;
            color: #495057;
        }}
        .flag-tag.high {{ background: #f8d7da; color: #721c24; }}
        .flag-tag.medium {{ background: #fff3cd; color: #856404; }}
        .flag-tag.low {{ background: #d1ecf1; color: #0c5460; }}
        
        .stale-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            background: #f8d7da;
            color: #721c24;
        }}
        
        .coverage-stacked {{
            display: flex;
            height: 30px;
            border-radius: 8px;
            overflow: hidden;
            margin: 12px 0;
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
            gap: 15px;
            margin: 12px 0;
            font-size: 0.85rem;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .legend-color {{
            width: 16px;
            height: 16px;
            border-radius: 3px;
        }}
        
        .filter-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: flex-end;
            margin-bottom: 15px;
            padding: 12px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .filter-group label {{
            font-size: 0.75rem;
            font-weight: 600;
            color: #495057;
        }}
        .filter-group input, .filter-group select {{
            padding: 6px 10px;
            border: 1px solid #ced4da;
            border-radius: 5px;
            font-size: 0.85rem;
            min-width: 130px;
        }}
        .search-box {{ flex: 1; min-width: 200px; }}
        .search-box input {{ width: 100%; padding: 8px 12px; }}
        .filter-stats {{ font-size: 0.85rem; color: #666; padding: 8px 0; }}
        .clear-filters {{
            background: #e9ecef;
            color: #495057;
            border: none;
            padding: 6px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.8rem;
        }}
        
        .table-container {{ overflow-x: auto; margin-top: 12px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e9ecef; }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
            position: sticky;
            top: 0;
            cursor: pointer;
            white-space: nowrap;
        }}
        th:hover {{ background: #e9ecef; }}
        th .sort-icon {{ margin-left: 4px; opacity: 0.3; font-size: 0.7rem; }}
        th.sorted-asc .sort-icon, th.sorted-desc .sort-icon {{ opacity: 1; }}
        th.sorted-asc .sort-icon::after {{ content: '▲'; }}
        th.sorted-desc .sort-icon::after {{ content: '▼'; }}
        th:not(.sorted-asc):not(.sorted-desc) .sort-icon::after {{ content: '⇅'; }}
        tr:hover {{ background: #f8f9fa; }}
        tr.hidden {{ display: none; }}
        
        .status-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
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
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.7rem;
            margin: 1px;
        }}
        .mitre-tag {{
            display: inline-block;
            background: #6f42c1;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.7rem;
        }}
        
        .log-group {{ margin-bottom: 15px; }}
        .log-group h3 {{
            background: #f8f9fa;
            padding: 10px 12px;
            border-radius: 6px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            font-size: 0.9rem;
            margin: 0;
        }}
        .log-group .count {{
            background: #dc3545;
            color: white;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8rem;
        }}
        .collapse-content.hidden {{ display: none; }}
        
        .info-box {{
            background: #e8f4fd;
            border-left: 4px solid #1a73e8;
            padding: 12px 15px;
            margin: 12px 0;
            border-radius: 0 6px 6px 0;
            font-size: 0.9rem;
        }}
        .info-box.warning {{ background: #fff3cd; border-left-color: #ffc107; }}
        .info-box.success {{ background: #d4edda; border-left-color: #28a745; }}
        .info-box.danger {{ background: #f8d7da; border-left-color: #dc3545; }}
        
        .gb-cell {{ text-align: right; font-family: 'Courier New', monospace; }}
        
        .confidence-indicator {{
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 4px;
        }}
        .confidence-high {{ background: #28a745; }}
        .confidence-medium {{ background: #ffc107; }}
        .confidence-low {{ background: #dc3545; }}
        
        @media print {{
            .filter-bar, .btn {{ display: none !important; }}
            .section {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SecOps Rule Comparison Report v10</h1>
            <p>Enhanced Analysis with Quality Scoring &amp; Dynamic Detection</p>
            <div class="header-meta">
                Generated: {timestamp}
                {f' | Data Period: {date_range_str}' if date_range_str else ''}
            </div>
            <button class="btn" onclick="window.print()">PDF</button>
            <button class="btn secondary" onclick="exportToCSV()">Export CSV</button>
        </header>
        
        <!-- EXECUTIVE SUMMARY -->
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
                <div class="value">{summary['conservative_coverage_pct']:.1f}%</div>
                <div class="label">Coverage</div>
            </div>
            <div class="summary-card" style="border: 2px solid {quality_color(summary['average_quality_score'])};">
                <div class="value" style="color: {quality_color(summary['average_quality_score'])};">{summary['average_quality_score']:.0f}</div>
                <div class="label">Avg Quality</div>
            </div>
            <div class="summary-card danger">
                <div class="value">{summary['unmapped_events']}</div>
                <div class="label">Unmapped</div>
            </div>
            <div class="summary-card warning">
                <div class="value">{summary['stale_rules_count']}</div>
                <div class="label">Stale Rules</div>
            </div>
        </div>
        
        <!-- QUALITY & ANALYSIS OVERVIEW -->
        <div class="section">
            <h2>Rule Quality &amp; Analysis Overview</h2>
            
            <div class="metrics-row">
                <div class="metric-box">
                    <div class="big-number" style="color: {quality_color(summary['average_quality_score'])};">{summary['average_quality_score']:.0f}<span style="font-size: 1rem;">/100</span></div>
                    <div class="metric-label">Average Quality Score</div>
                    <div class="quality-bar">
                        <div class="quality-fill" style="width: {summary['average_quality_score']}%; background: {quality_color(summary['average_quality_score'])};"></div>
                    </div>
                </div>
                <div class="metric-box">
                    <div style="display: flex; justify-content: center; gap: 8px; margin-bottom: 10px;">
                        <span class="grade-badge grade-A">{quality_summary['grade_distribution']['A']}</span>
                        <span class="grade-badge grade-B">{quality_summary['grade_distribution']['B']}</span>
                        <span class="grade-badge grade-C">{quality_summary['grade_distribution']['C']}</span>
                        <span class="grade-badge grade-D">{quality_summary['grade_distribution']['D']}</span>
                        <span class="grade-badge grade-F">{quality_summary['grade_distribution']['F']}</span>
                    </div>
                    <div class="metric-label">Grade Distribution (A-F)</div>
                </div>
                <div class="metric-box">
                    <div class="big-number" style="color: #6f42c1;">{summary['dynamic_rules_count']}</div>
                    <div class="metric-label">Dynamic Rules (Need Manual Review)</div>
                </div>
                <div class="metric-box">
                    <div class="big-number" style="color: #dc3545;">{summary['stale_rules_count']}</div>
                    <div class="metric-label">Stale Rules (&gt;12 months old)</div>
                </div>
            </div>
            
            <div class="info-box">
                <strong>Quality Score Components:</strong> Specificity (25pts) + Triggering (25pts) + MITRE Mapping (15pts) + Description (10pts) + Freshness (15pts) + Relevance (10pts)
            </div>
            
            <h3>Parsing Confidence &amp; Dynamic Analysis</h3>
            <table style="max-width: 600px;">
                <tr>
                    <td><span class="confidence-indicator confidence-high"></span> High Confidence Parsing</td>
                    <td><strong>{dynamic_analysis['parsing_confidence']['high']}</strong> rules</td>
                </tr>
                <tr>
                    <td><span class="confidence-indicator confidence-medium"></span> Medium Confidence (regex/multi-event)</td>
                    <td><strong>{dynamic_analysis['parsing_confidence']['medium']}</strong> rules</td>
                </tr>
                <tr>
                    <td><span class="confidence-indicator confidence-low"></span> Low Confidence (complex logic)</td>
                    <td><strong>{dynamic_analysis['parsing_confidence']['low']}</strong> rules</td>
                </tr>
                <tr><td colspan="2" style="border-top: 2px solid #e9ecef;"></td></tr>
                <tr>
                    <td>Rules using Reference Lists</td>
                    <td><strong>{dynamic_analysis['rules_with_reference_lists']}</strong></td>
                </tr>
                <tr>
                    <td>Rules using Entity Graph</td>
                    <td><strong>{dynamic_analysis['rules_with_entity_graph']}</strong></td>
                </tr>
                <tr>
                    <td>Rules using Prevalence Functions</td>
                    <td><strong>{dynamic_analysis['rules_with_prevalence']}</strong></td>
                </tr>
                <tr>
                    <td>Multi-Event Correlation Rules</td>
                    <td><strong>{dynamic_analysis['multi_event_rules']}</strong></td>
                </tr>
                <tr>
                    <td>Rules with Regex Patterns</td>
                    <td><strong>{dynamic_analysis['regex_rules']}</strong></td>
                </tr>
            </table>
            
            <div class="info-box warning" style="margin-top: 15px;">
                <strong>⚠️ {summary['dynamic_rules_count']} rules use dynamic conditions</strong> (reference lists, entity graph, prevalence) that cannot be statically analyzed. These rules need manual review to verify coverage.
            </div>
        </div>
        
        <!-- DETECTION COVERAGE -->
        <div class="section">
            <h2>Detection Coverage</h2>
            
            <div class="coverage-stacked">
                <div style="width: {summary['exact_matches'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%; background: #28a745;">{summary['exact_matches']}</div>
                <div style="width: {summary['partial_matches'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%; background: #17a2b8;">{summary['partial_matches']}</div>
                <div style="width: {summary['broad_matches'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%; background: #ffc107; color: #333;">{summary['broad_matches']}</div>
                <div style="width: {summary['unmapped_events'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%; background: #dc3545;">{summary['unmapped_events']}</div>
            </div>
            
            <div class="coverage-legend">
                <div class="legend-item"><div class="legend-color" style="background: #28a745;"></div><span><strong>Exact ({summary['exact_matches']})</strong> - {summary['exact_matches'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%</span></div>
                <div class="legend-item"><div class="legend-color" style="background: #17a2b8;"></div><span><strong>Partial ({summary['partial_matches']})</strong> - {summary['partial_matches'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%</span></div>
                <div class="legend-item"><div class="legend-color" style="background: #ffc107;"></div><span><strong>Broad ({summary['broad_matches']})</strong> - {summary['broad_matches'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%</span></div>
                <div class="legend-item"><div class="legend-color" style="background: #dc3545;"></div><span><strong>Unmapped ({summary['unmapped_events']})</strong> - {summary['unmapped_events'] / summary['total_event_combinations'] * 100 if summary['total_event_combinations'] else 0:.1f}%</span></div>
            </div>
            
            <div class="info-box success">
                <strong>Static Coverage: {summary['conservative_coverage_pct']:.1f}%</strong> (Exact + Partial) | 
                <strong>Dynamic Rules: {summary['dynamic_rules_count']}</strong> need manual verification
            </div>
        </div>
'''
    
    # Stale Rules Section
    if analysis['stale_rules']:
        html += '''
        <div class="section">
            <h2>⚠️ Stale Rules (Not Updated in 12+ Months)</h2>
            <div class="info-box danger">
                These enabled rules haven't been updated in over a year. They may be targeting outdated attack patterns or have configuration drift.
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr><th>Rule Name</th><th>Days Since Update</th><th>Severity</th><th>Triggers</th><th>Quality</th></tr>
                    </thead>
                    <tbody>
'''
        for rule in sorted(analysis['stale_rules'], key=lambda x: x['days_since_update'] or 0, reverse=True)[:15]:
            html += f'''<tr>
                <td><strong>{rule['name']}</strong></td>
                <td><span class="stale-badge">{rule['days_since_update']} days</span></td>
                <td>{rule['severity']}</td>
                <td>{rule['trigger_count']:,}</td>
                <td><span class="grade-badge grade-{rule['quality_grade']}">{rule['quality_grade']}</span></td>
            </tr>'''
        html += '</tbody></table></div></div>'
    
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
        
        for vol in analysis['weekly_volumes'][:15]:
            html += f'<tr><td><strong>{vol["log_type"]}</strong></td><td class="gb-cell">{vol["total_gb"]:.2f}</td>'
            for w in range(1, min(num_weeks + 1, 7)):
                html += f'<td class="gb-cell">{vol.get(f"week_{w}_gb", 0):.2f}</td>'
            html += '</tr>'
        html += '</tbody></table></div></div>'
    
    # Rules Table
    html += f'''
        <div class="section">
            <h2>All Rules</h2>
            
            <div class="filter-bar">
                <div class="filter-group search-box">
                    <label>Search</label>
                    <input type="text" id="searchInput" placeholder="Rule name..." onkeyup="filterTable()">
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
                    <label>Grade</label>
                    <select id="gradeFilter" onchange="filterTable()">
                        <option value="">All</option>
                        <option value="A">A (80+)</option>
                        <option value="B">B (60-79)</option>
                        <option value="C">C (40-59)</option>
                        <option value="D">D (20-39)</option>
                        <option value="F">F (&lt;20)</option>
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
                <div class="filter-group">
                    <label>Event Type</label>
                    <select id="eventTypeFilter" onchange="filterTable()">
                        <option value="">All</option>
                        {event_options}
                    </select>
                </div>
                <div class="filter-group">
                    <label>Product Event</label>
                    <select id="productEventFilter" onchange="filterTable()">
                        <option value="">All</option>
                        {product_options}
                    </select>
                </div>
                <div class="filter-group">
                    <label>Flags</label>
                    <select id="flagFilter" onchange="filterTable()">
                        <option value="">All</option>
                        <option value="dynamic">Has Dynamic Conditions</option>
                        <option value="stale">Stale (&gt;12mo)</option>
                        <option value="regex">Uses Regex</option>
                        <option value="multi">Multi-Event</option>
                    </select>
                </div>
                <button class="clear-filters" onclick="clearFilters()">Clear</button>
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
                            <th onclick="sortTable('rulesTable', 2)">Spec <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 3)">Quality <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 4)">Severity <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 5)">Triggers <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 6)">MITRE <span class="sort-icon"></span></th>
                            <th>Flags</th>
                            <th onclick="sortTable('rulesTable', 8)">Log Types <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 9)">Event Types <span class="sort-icon"></span></th>
                            <th onclick="sortTable('rulesTable', 10)">Product Events <span class="sort-icon"></span></th>
                        </tr>
                    </thead>
                    <tbody>
'''
    
    sorted_rules = sorted(analysis['rule_status'], key=lambda x: (-x['quality_score'], x['name']))
    for rule in sorted_rules:
        enabled_class = 'status-enabled' if rule['enabled'] else 'status-disabled'
        enabled_text = 'Enabled' if rule['enabled'] else 'Disabled'
        spec_class = f"status-{rule['specificity']}"
        spec_text = rule['specificity'].title()
        
        # Flags
        flags_html = ''
        if rule['dynamic_flags']:
            for flag_name, flag_info in list(rule['dynamic_flags'].items())[:3]:
                flags_html += f'<span class="flag-tag {flag_info["severity"]}">{flag_name}</span>'
        if rule['is_stale']:
            flags_html += '<span class="flag-tag high">stale</span>'
        if rule['has_regex']:
            flags_html += '<span class="flag-tag low">regex</span>'
        if rule['is_multi_event']:
            flags_html += '<span class="flag-tag medium">multi</span>'
        if not flags_html:
            flags_html = '-'
        
        # Data attributes for filtering
        has_dynamic = '1' if rule['dynamic_flags'] else '0'
        is_stale = '1' if rule['is_stale'] else '0'
        has_regex = '1' if rule['has_regex'] else '0'
        is_multi = '1' if rule['is_multi_event'] else '0'
        
        log_types_str = ' '.join(lt for lt in rule['log_types'] if not lt.startswith('REGEX:'))
        log_display = ''.join(f'<span class="log-tag">{lt}</span>' for lt in rule['log_types'][:2] if not lt.startswith('REGEX:'))
        if len(rule['log_types']) > 2:
            log_display += f' +{len(rule["log_types"])-2}'
        if not log_display:
            log_display = '<em style="color:#999">-</em>'
        
        # Event types
        event_types_str = ' '.join(et for et in rule['event_types'] if not et.startswith('REGEX:'))
        event_display = ''.join(f'<span class="log-tag" style="background:#e8f5e9;color:#2e7d32;">{et}</span>' for et in rule['event_types'][:2] if not et.startswith('REGEX:'))
        if len(rule['event_types']) > 2:
            event_display += f' +{len(rule["event_types"])-2}'
        if not event_display:
            event_display = '<em style="color:#999">-</em>'
        
        # Product event types
        product_types_str = ' '.join(pt for pt in rule['product_event_types'] if not pt.startswith('REGEX:'))
        product_display = ''.join(f'<span class="log-tag" style="background:#fff3e0;color:#e65100;">{pt[:20]}</span>' for pt in rule['product_event_types'][:2] if not pt.startswith('REGEX:'))
        if len(rule['product_event_types']) > 2:
            product_display += f' +{len(rule["product_event_types"])-2}'
        if not product_display:
            product_display = '<em style="color:#999">-</em>'
        
        html += f'''<tr data-name="{rule['name'].lower()}" data-status="{enabled_text}" data-spec="{rule['specificity']}" data-grade="{rule['quality_grade']}" data-severity="{rule['severity']}" data-logtypes="{log_types_str.lower()}" data-eventtypes="{event_types_str.lower()}" data-producttypes="{product_types_str.lower()}" data-dynamic="{has_dynamic}" data-stale="{is_stale}" data-regex="{has_regex}" data-multi="{is_multi}">
            <td><strong>{rule['name'][:50]}{'...' if len(rule['name']) > 50 else ''}</strong></td>
            <td><span class="status-badge {enabled_class}">{enabled_text}</span></td>
            <td><span class="status-badge {spec_class}">{spec_text}</span></td>
            <td><span class="grade-badge grade-{rule['quality_grade']}">{rule['quality_grade']}</span> {rule['quality_score']}</td>
            <td>{rule['severity']}</td>
            <td>{rule['trigger_count']:,}</td>
            <td>{f'<span class="mitre-tag">{rule["mitre"][:15]}</span>' if rule['mitre'] else '-'}</td>
            <td>{flags_html}</td>
            <td>{log_display}</td>
            <td>{event_display}</td>
            <td>{product_display}</td>
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
            <h2>Unmapped Events (Blind Spots)</h2>
            <div class="info-box danger">
                These events have NO detection rules. Prioritize high-volume event types.
            </div>
'''
        for log_type in sorted(unmapped_by_log.keys()):
            evts = unmapped_by_log[log_type]
            total = sum(e['event_count'] for e in evts)
            html += f'''
            <div class="log-group">
                <h3 onclick="this.nextElementSibling.classList.toggle('hidden')">
                    {log_type} <span class="count">{len(evts)} types ({total:,} events)</span>
                </h3>
                <div class="collapse-content">
                    <table><thead><tr><th>Event Type</th><th>Product Event</th><th>Count</th></tr></thead><tbody>
'''
            for evt in sorted(evts, key=lambda x: x['event_count'], reverse=True)[:15]:
                html += f'<tr><td>{evt["event_type"] or "-"}</td><td>{evt["product_event_type"] or "-"}</td><td>{evt["event_count"]:,}</td></tr>'
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
            const grade = document.getElementById('gradeFilter').value;
            const severity = document.getElementById('severityFilter').value;
            const logType = document.getElementById('logTypeFilter').value.toLowerCase();
            const eventType = document.getElementById('eventTypeFilter').value.toLowerCase();
            const productType = document.getElementById('productEventFilter').value.toLowerCase();
            const flag = document.getElementById('flagFilter').value;
            
            const rows = document.querySelectorAll('#rulesTable tbody tr');
            let visible = 0;
            
            rows.forEach(row => {
                const d = row.dataset;
                let show = true;
                
                if (search && !d.name.includes(search)) show = false;
                if (status && d.status !== status) show = false;
                if (spec && d.spec !== spec) show = false;
                if (grade && d.grade !== grade) show = false;
                if (severity && d.severity !== severity) show = false;
                if (logType && !(d.logtypes || '').includes(logType)) show = false;
                if (eventType && !(d.eventtypes || '').includes(eventType)) show = false;
                if (productType && !(d.producttypes || '').includes(productType)) show = false;
                
                if (flag === 'dynamic' && d.dynamic !== '1') show = false;
                if (flag === 'stale' && d.stale !== '1') show = false;
                if (flag === 'regex' && d.regex !== '1') show = false;
                if (flag === 'multi' && d.multi !== '1') show = false;
                
                row.classList.toggle('hidden', !show);
                if (show) visible++;
            });
            
            document.getElementById('visibleCount').textContent = visible;
        }
        
        function clearFilters() {
            document.querySelectorAll('.filter-bar select').forEach(s => s.value = '');
            document.getElementById('searchInput').value = '';
            filterTable();
        }
        
        function sortTable(tableId, col) {
            const table = document.getElementById(tableId);
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const th = table.querySelectorAll('th')[col];
            const asc = !th.classList.contains('sorted-asc');
            
            table.querySelectorAll('th').forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
            th.classList.add(asc ? 'sorted-asc' : 'sorted-desc');
            
            rows.sort((a, b) => {
                let av = a.cells[col]?.textContent.trim().replace(/,/g, '') || '';
                let bv = b.cells[col]?.textContent.trim().replace(/,/g, '') || '';
                const an = parseFloat(av), bn = parseFloat(bv);
                if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
                return asc ? av.localeCompare(bv) : bv.localeCompare(av);
            });
            
            rows.forEach(r => tbody.appendChild(r));
        }
        
        function exportToCSV() {
            const rows = document.querySelectorAll('#rulesTable tbody tr:not(.hidden)');
            let csv = 'Rule Name,Status,Specificity,Quality Score,Grade,Severity,Triggers,MITRE,Flags,Log Types,Event Types,Product Events\\n';
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                const data = [0,1,2,3,4,5,6,7,8,9,10].map(i => `"${(cells[i]?.textContent || '').trim().replace(/"/g, '""')}"`);
                csv += data.join(',') + '\\n';
            });
            const blob = new Blob([csv], {type: 'text/csv'});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'rules_export.csv';
            a.click();
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
    print("  SecOps Rule Comparison Tool v10")
    print("  Enhanced Analysis with Quality Scoring")
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
    print(f"  - Avg Quality: {analysis['summary']['average_quality_score']:.0f}/100")
    print(f"  - Dynamic Rules: {analysis['summary']['dynamic_rules_count']}")
    print(f"  - Stale Rules: {analysis['summary']['stale_rules_count']}")
    
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
