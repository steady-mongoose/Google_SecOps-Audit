#!/usr/bin/env python3
"""
YARAL Event Mapping Comparison Tool - v3.3 (Coverage Gap Analysis)
===================================================================
Shows detection rules from CSV + coverage analysis + fast PDF export
With client-side PDF generation for instant downloads

v3.3 Changes:
- NEW: "Why Gap Exists" column in Detailed Unmapped Events to explain reasons for gaps
- More specific recommendations based on matched patterns
- Refined categorization logic for better accuracy
- Improved summary statistics with breakdown verification
- Enhanced pattern matching for review needed vs unmapped

v3.2 Changes:
- NEW: Coverage Gap Analysis section with per-event-type breakdown
- Shows Covered vs Uncovered counts for each event type
- Visual coverage bars with color-coded status (Complete/Good/Gap/None)
- High-Value Gaps column flags security-critical uncovered events
- Expandable rows - click to see specific covered/uncovered product events
- Reorganized report: Rules → Coverage Gap Analysis → Log Volume → Detailed Unmapped

v3.1 Changes:
- Unmapped events now classified as "Unmapped" or "Review Needed"
- Review Needed: Events that should be checked against existing rule libraries
- Unmapped: Events that likely need new detection rules created
- Added Recommendation column with actionable guidance
- Summary cards show breakdown of unmapped vs review needed
- Status legend added to Unmapped Event Combinations section

v3.0 Changes:
- Support for new YARAL query with expanded match clause
- Handles event_type_arr outcome field (array of distinct event types)
- New columns: rule_description, rule_severity, rule_state, rule_type
- Improved array parsing for CSV exports
- Enhanced report with rule metadata breakdown
- Filters out STAGE_/DEV_/_PR_ rules automatically handled by query

Repository: https://github.com/steady-mongoose/Google_SecOps-Audit
"""

import csv
import tkinter as tk
from tkinter import filedialog
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import webbrowser
import re
import ast


VERSION = "3.3.0"


def parse_array_field(value):
    """
    Parse array field from CSV that may be in various formats:
    - JSON-style array: ["EVENT1", "EVENT2"]
    - Comma-separated in brackets: [EVENT1, EVENT2]
    - Plain comma-separated: EVENT1, EVENT2
    - Single value: EVENT1
    
    Returns a list of strings (lowercase for comparison)
    """
    if not value or value.strip() == '' or value.strip().lower() in ('[]', 'null', 'none'):
        return []
    
    value = value.strip()
    
    # Try JSON-style array first
    if value.startswith('[') and value.endswith(']'):
        inner = value[1:-1].strip()
        if not inner:
            return []
        
        # Try ast.literal_eval for proper parsing
        try:
            parsed = ast.literal_eval(value)
            if isinstance(parsed, list):
                return [str(item).strip().lower() for item in parsed if item]
        except (ValueError, SyntaxError):
            pass
        
        # Fallback: split by comma, clean up quotes
        items = []
        for item in inner.split(','):
            cleaned = item.strip().strip('"\'').strip()
            if cleaned and cleaned.lower() not in ('null', 'none', ''):
                items.append(cleaned.lower())
        return items
    
    # Plain comma-separated or single value
    if ',' in value:
        return [item.strip().lower() for item in value.split(',') if item.strip()]
    
    return [value.lower()]


def get_column_value(row, *possible_names):
    """Try to get a column value from multiple possible column names"""
    for name in possible_names:
        if name in row and row[name]:
            return row[name].strip()
    return ""


def load_detection_rules_v3(file_path):
    """
    Load detection rules from CSV - v3.0 format
    
    Expected columns from new YARAL query:
    - rule_name (match)
    - rule_description (match)
    - rule_severity (match)
    - rule_state (match)
    - rule_type (match)
    - log_type (match)
    - product_event (match)
    - event_type_arr (outcome - array)
    
    Returns:
    - detection_rules: list of rule dicts with all metadata
    - detection_tuples: set of (log_type, event_type, product_event) for coverage calc
    """
    detection_rules = []
    detection_tuples = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            print(f"  Column names found: {reader.fieldnames}")
            
            row_count = 0
            for row in reader:
                row_count += 1
                
                # Get rule metadata - handle various column name formats
                rule_name = get_column_value(row, 
                    'rule_name', 'Rulename', 'Rule Name', 'RuleName', 'RULE_NAME')
                rule_description = get_column_value(row,
                    'rule_description', 'Ruledescription', 'Rule Description', 'description', 'RULE_DESCRIPTION')
                rule_severity = get_column_value(row,
                    'rule_severity', 'Ruleseverity', 'Rule Severity', 'severity', 'RULE_SEVERITY')
                rule_state = get_column_value(row,
                    'rule_state', 'Rulestate', 'Rule State', 'alert_state', 'RULE_STATE')
                rule_type = get_column_value(row,
                    'rule_type', 'Ruletype', 'Rule Type', 'type', 'RULE_TYPE')
                
                # Get event metadata
                log_type = get_column_value(row, 
                    'log_type', 'Logtype', 'Log Type', 'LOG_TYPE').lower()
                product_event = get_column_value(row,
                    'product_event', 'Productevent', 'product_event_type', 'Product Event', 'PRODUCT_EVENT')
                
                # Get event_type_arr (outcome array field)
                event_type_arr_raw = get_column_value(row,
                    'event_type_arr', 'Eventtypearr', 'event_type_arr', 'EVENT_TYPE_ARR',
                    # Fallback to old single-value columns
                    'event_type', 'Eventtype', 'Event Type', 'EVENT_TYPE')
                
                # Parse the array field
                event_types = parse_array_field(event_type_arr_raw)
                
                # Skip if no rule name or key fields missing
                if not rule_name or not log_type or not product_event:
                    continue
                
                # Store the rule with all metadata
                rule_data = {
                    'rule_name': rule_name,
                    'rule_description': rule_description[:100] + '...' if len(rule_description) > 100 else rule_description,
                    'rule_severity': rule_severity,
                    'rule_state': rule_state,
                    'rule_type': rule_type,
                    'log_type': log_type,
                    'product_event': product_event,
                    'event_types': event_types,  # List of event types
                    'event_type_count': len(event_types)
                }
                detection_rules.append(rule_data)
                
                # Build detection tuples for coverage calculation
                # Each event_type in the array creates a coverage tuple
                if log_type and product_event:
                    for event_type in event_types:
                        if event_type and event_type != "eventtype_unspecified":
                            detection_tuples.add((log_type, event_type, product_event.lower()))
                    
                    # Also add tuple without event_type for broader matching
                    if not event_types:
                        # If no specific event types, treat as covering all for that log_type/product
                        detection_tuples.add((log_type, '*', product_event.lower()))
            
            print(f"  Processed {row_count} rows")
            print(f"✓ Loaded {len(detection_rules)} detection rules")
            print(f"✓ Created {len(detection_tuples)} coverage tuples")
            return detection_rules, detection_tuples
    
    except Exception as e:
        print(f"✗ Error loading detection file: {e}")
        import traceback
        traceback.print_exc()
        return [], set()


def load_event_results(file_path):
    """Load raw event query results from CSV"""
    event_tuples = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            print(f"  Column names found: {reader.fieldnames}")
            
            row_count = 0
            for row in reader:
                row_count += 1
                log_type = get_column_value(row, 'log_type', 'Logtype', 'logtype', 'LogType', 'LOG_TYPE').lower()
                event_type = get_column_value(row, 'event_type', 'Eventtype', 'eventtype', 'EventType', 'EVENT_TYPE').lower()
                product_event_type = get_column_value(row, 'product_event_type', 'Productevent', 'productevent', 'ProductEvent', 'PRODUCT_EVENT_TYPE', 'product_event').lower()
                
                if log_type and event_type and product_event_type and event_type != "eventtype_unspecified":
                    event_tuples.add((log_type, event_type, product_event_type))
            
            print(f"  Processed {row_count} rows")
            print(f"✓ Loaded {len(event_tuples)} unique combinations")
            return event_tuples
    except Exception as e:
        print(f"✗ Error loading event file: {e}")
        return set()


def load_log_volume_data(file_path):
    """Load log volume query results from CSV"""
    log_volume_data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            print(f"  Column names found: {reader.fieldnames}")
            
            row_count = 0
            for row in reader:
                row_count += 1
                log_type = get_column_value(row, 'log_type', 'Logtype', 'logtype', 'LogType', 'LOG_TYPE')
                event_count = get_column_value(row, 'event_count', 'event_count', 'EventCount', 'EVENT_COUNT')
                week_gigabytes = get_column_value(row, 'week_gigabytes', 'week_gigabytes', 'WeekGigabytes', 'WEEK_GIGABYTES')
                week = get_column_value(row, 'week', 'Week', 'WEEK')
                
                if log_type:
                    log_volume_data.append({'log_type': log_type, 'event_count': event_count, 'week_gigabytes': week_gigabytes, 'week': week})
            
            print(f"  Processed {row_count} rows")
            print(f"✓ Loaded {len(log_volume_data)} log volume records")
            return log_volume_data
    except Exception as e:
        print(f"⚠️  Warning: Could not load log volume file: {e}")
        return []


def calculate_data_timespan(log_volume_data):
    """Calculate the time span of the data"""
    if not log_volume_data:
        return None, 0
    try:
        dates = []
        for record in log_volume_data:
            week_str = record.get('week', '').strip()
            if week_str:
                try:
                    week_date = datetime.strptime(week_str, '%Y-%m-%d')
                    dates.append(week_date)
                except ValueError:
                    pass
        if len(dates) < 1:
            return None, 0
        dates.sort()
        start_date = dates[0]
        end_date = dates[-1]
        days_diff = (end_date - start_date).days
        weeks_count = (days_diff // 7) + 1
        months_count = days_diff // 30
        if weeks_count <= 4:
            if weeks_count == 1:
                date_range_str = f"{start_date.strftime('%B %d, %Y')} (1 week)"
            else:
                date_range_str = f"{start_date.strftime('%b %d')} - {end_date.strftime('%b %d, %Y')} ({weeks_count} weeks)"
        else:
            if months_count < 1:
                date_range_str = f"{start_date.strftime('%b %d')} - {end_date.strftime('%b %d, %Y')} ({weeks_count} weeks)"
            elif months_count == 1:
                date_range_str = f"{start_date.strftime('%B %d')} - {end_date.strftime('%B %d, %Y')} (1 month)"
            else:
                date_range_str = f"{start_date.strftime('%b %d, %Y')} - {end_date.strftime('%b %d, %Y')} ({months_count} months)"
        return date_range_str, weeks_count
    except Exception as e:
        print(f"⚠️  Warning: Could not parse date range: {e}")
        return None, 0


def compare_results(detection_tuples, event_tuples):
    """
    Find unmapped combinations with support for wildcard matching
    """
    mapped = set()
    unmapped = set()
    
    # Extract wildcard rules (those with '*' event_type)
    wildcard_coverage = set()
    for log_type, event_type, product_event in detection_tuples:
        if event_type == '*':
            wildcard_coverage.add((log_type, product_event))
    
    for event_tuple in event_tuples:
        log_type, event_type, product_event = event_tuple
        
        # Check direct match
        if event_tuple in detection_tuples:
            mapped.add(event_tuple)
        # Check wildcard match (rule covers all event types for this log_type/product)
        elif (log_type, product_event) in wildcard_coverage:
            mapped.add(event_tuple)
        else:
            unmapped.add(event_tuple)
    
    return mapped, unmapped


def categorize_unmapped_events(unmapped):
    """
    Categorize unmapped events into 'unmapped' vs 'review_needed'
    Returns counts for summary display
    """
    # Event types that typically warrant "Review Needed" status
    REVIEW_NEEDED_PATTERNS = [
        'user_login', 'user_logout', 'authentication', 'auth_',
        'process_launch', 'process_', 'file_creation', 'file_modification',
        'network_connection', 'network_', 'dns_', 'http_',
        'registry_', 'service_', 'scheduled_task',
        'resource_creation', 'resource_deletion', 'resource_read',
        'group_', 'user_creation', 'user_change',
        'email_', 'scan_', 'status_'
    ]
    
    # Product events that typically have existing detection rules
    REVIEW_NEEDED_PRODUCTS = [
        'assumerole', 'getobject', 'putobject', 'deleteobject',
        'createuser', 'deleteuser', 'attachpolicy', 'detachpolicy',
        'createbucket', 'deletebucket', 'putbucketpolicy',
        'authorizesg', 'revokesecurity', 'createkey', 'decrypt',
        'consolelogin', 'switchrole', 'createloginprofile',
        'runinstances', 'terminateinstances', 'stopinstances',
        'describe', 'list', 'get'
    ]
    
    unmapped_count = 0
    review_count = 0
    
    for log_type, event_type, product_event in unmapped:
        event_lower = event_type.lower()
        product_lower = product_event.lower()
        
        is_review = False
        for pattern in REVIEW_NEEDED_PATTERNS:
            if pattern in event_lower:
                is_review = True
                break
        
        if not is_review:
            for pattern in REVIEW_NEEDED_PRODUCTS:
                if pattern in product_lower:
                    is_review = True
                    break
        
        if is_review:
            review_count += 1
        else:
            unmapped_count += 1
    
    return unmapped_count, review_count


def analyze_coverage_gaps(mapped, unmapped):
    """
    Analyze coverage gaps by log_type and event_type combination.
    Returns a structured analysis for the coverage gap report.
    """
    # Build coverage data structure: {log_type: {event_type: {'covered': set(), 'uncovered': set()}}}
    coverage_data = defaultdict(lambda: defaultdict(lambda: {'covered': set(), 'uncovered': set()}))
    
    # Add mapped events
    for log_type, event_type, product_event in mapped:
        coverage_data[log_type][event_type]['covered'].add(product_event)
    
    # Add unmapped events
    for log_type, event_type, product_event in unmapped:
        coverage_data[log_type][event_type]['uncovered'].add(product_event)
    
    # Security-critical product events to flag
    HIGH_VALUE_EVENTS = {
        'assumerole', 'decrypt', 'createuser', 'deleteuser', 'attachpolicy',
        'detachpolicy', 'createaccesskey', 'deleteaccesskey', 'putbucketpolicy',
        'deletebucket', 'createloginprofile', 'updateloginprofile', 'consolelogin',
        'switchrole', 'createkey', 'disablekey', 'schedulekey', 'authorizesg',
        'revokesecuritygroupingress', 'revokesecuritygroupegress', 'createvpc',
        'deletevpc', 'modifyinstanceattribute', 'stopinstances', 'terminateinstances',
        'runinstances', 'createfunction', 'updatefunctioncode', 'invoke',
        'puteventselectors', 'stoptrail', 'deletetrail', 'updatetrail'
    }
    
    # Build analysis results
    analysis = []
    for log_type in sorted(coverage_data.keys()):
        log_analysis = {
            'log_type': log_type,
            'event_types': [],
            'total_covered': 0,
            'total_uncovered': 0
        }
        
        for event_type in sorted(coverage_data[log_type].keys()):
            data = coverage_data[log_type][event_type]
            covered_count = len(data['covered'])
            uncovered_count = len(data['uncovered'])
            total = covered_count + uncovered_count
            coverage_pct = (covered_count / total * 100) if total > 0 else 0
            
            # Identify high-value uncovered events
            high_value_uncovered = []
            for pe in data['uncovered']:
                pe_lower = pe.lower()
                for hv in HIGH_VALUE_EVENTS:
                    if hv in pe_lower:
                        high_value_uncovered.append(pe)
                        break
            
            # Determine status
            if coverage_pct == 100:
                status = 'complete'
            elif coverage_pct >= 70:
                status = 'good'
            elif coverage_pct > 0:
                status = 'gap'
            else:
                status = 'none'
            
            event_analysis = {
                'event_type': event_type,
                'covered': covered_count,
                'uncovered': uncovered_count,
                'coverage_pct': coverage_pct,
                'status': status,
                'covered_events': sorted(data['covered']),
                'uncovered_events': sorted(data['uncovered']),
                'high_value_uncovered': sorted(high_value_uncovered)
            }
            
            log_analysis['event_types'].append(event_analysis)
            log_analysis['total_covered'] += covered_count
            log_analysis['total_uncovered'] += uncovered_count
        
        # Calculate log-level coverage
        log_total = log_analysis['total_covered'] + log_analysis['total_uncovered']
        log_analysis['coverage_pct'] = (log_analysis['total_covered'] / log_total * 100) if log_total > 0 else 0
        
        analysis.append(log_analysis)
    
    return analysis


def group_by_logtype(unmapped):
    """Group unmapped events by log type"""
    grouped = defaultdict(list)
    for log_type, event_type, product_event_type in unmapped:
        grouped[log_type].append((event_type, product_event_type))
    return grouped


def get_severity_badge(severity):
    """Return HTML badge for severity level"""
    severity_lower = severity.lower() if severity else ''
    if 'critical' in severity_lower or 'high' in severity_lower:
        return f'<span class="severity-badge severity-high">{severity}</span>'
    elif 'medium' in severity_lower or 'med' in severity_lower:
        return f'<span class="severity-badge severity-medium">{severity}</span>'
    elif 'low' in severity_lower or 'info' in severity_lower:
        return f'<span class="severity-badge severity-low">{severity}</span>'
    return f'<span class="severity-badge">{severity}</span>'


def get_state_badge(state):
    """Return HTML badge for rule state"""
    state_lower = state.lower() if state else ''
    if 'alerting' in state_lower or 'enabled' in state_lower or 'active' in state_lower:
        return f'<span class="state-badge state-active">{state}</span>'
    elif 'disabled' in state_lower or 'inactive' in state_lower:
        return f'<span class="state-badge state-inactive">{state}</span>'
    return f'<span class="state-badge">{state}</span>'


def get_coverage_gap_section(coverage_analysis):
    """Generate HTML for the Coverage Gap Analysis section with expandable details"""
    
    html = """            <div class="section">
                <h2>📊 Coverage Gap Analysis</h2>
                <p style="color: #666; margin-bottom: 15px;">Analysis of detection coverage by log type and event type. Click any row to see specific product events.</p>
                <div class="status-legend" style="display: flex; gap: 15px; margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px; flex-wrap: wrap;">
                    <div><span class="coverage-status coverage-complete">✅ Complete</span> 100% coverage</div>
                    <div><span class="coverage-status coverage-good">✅ Good</span> 70-99% coverage</div>
                    <div><span class="coverage-status coverage-gap">⚠️ Gap</span> 1-69% coverage</div>
                    <div><span class="coverage-status coverage-none">🔴 No Coverage</span> 0% coverage</div>
                    <div><span class="high-value-flag">🚨 High Value</span> Security-critical events uncovered</div>
                </div>
"""
    
    for log_data in coverage_analysis:
        log_type = log_data['log_type'].upper()
        log_coverage = log_data['coverage_pct']
        total_covered = log_data['total_covered']
        total_uncovered = log_data['total_uncovered']
        
        # Determine log-level status color
        if log_coverage == 100:
            log_status_class = 'coverage-complete'
        elif log_coverage >= 70:
            log_status_class = 'coverage-good'
        elif log_coverage > 0:
            log_status_class = 'coverage-gap'
        else:
            log_status_class = 'coverage-none'
        
        html += f"""
                <div class="log-type-section">
                    <h3>{log_type} 
                        <span class="log-type-count">{total_covered + total_uncovered} total events</span>
                        <span class="coverage-status {log_status_class}" style="margin-left: 10px;">{log_coverage:.1f}% covered</span>
                    </h3>
                    <div class="table-wrapper">
                        <table class="coverage-table">
                            <thead>
                                <tr>
                                    <th>Event Type</th>
                                    <th style="text-align: center;">Covered</th>
                                    <th style="text-align: center;">Uncovered</th>
                                    <th style="text-align: center;">Coverage</th>
                                    <th>Coverage Bar</th>
                                    <th style="text-align: center;">Status</th>
                                    <th>High-Value Gaps</th>
                                </tr>
                            </thead>
                            <tbody>
"""
        
        for event_data in log_data['event_types']:
            event_type = event_data['event_type'].upper()
            covered = event_data['covered']
            uncovered = event_data['uncovered']
            coverage_pct = event_data['coverage_pct']
            status = event_data['status']
            high_value = event_data['high_value_uncovered']
            uncovered_events = event_data['uncovered_events']
            covered_events = event_data['covered_events']
            
            # Status badge
            if status == 'complete':
                status_badge = '<span class="coverage-status coverage-complete">✅ Complete</span>'
            elif status == 'good':
                status_badge = '<span class="coverage-status coverage-good">✅ Good</span>'
            elif status == 'gap':
                status_badge = '<span class="coverage-status coverage-gap">⚠️ Gap</span>'
            else:
                status_badge = '<span class="coverage-status coverage-none">🔴 No Coverage</span>'
            
            # High-value flags
            if high_value:
                hv_display = ', '.join([f'<code class="high-value-code">{hv}</code>' for hv in high_value[:3]])
                if len(high_value) > 3:
                    hv_display += f' <span class="more-badge">+{len(high_value)-3}</span>'
                hv_cell = f'<span class="high-value-flag">🚨</span> {hv_display}'
            else:
                hv_cell = '<span style="color: #999;">—</span>'
            
            # Coverage bar color
            if coverage_pct == 100:
                bar_color = '#2e7d32'
            elif coverage_pct >= 70:
                bar_color = '#4caf50'
            elif coverage_pct > 0:
                bar_color = '#ff9800'
            else:
                bar_color = '#f44336'
            
            # Build expandable details
            row_id = f"{log_data['log_type']}_{event_data['event_type']}".replace(' ', '_').lower()
            
            html += f"""                                <tr class="expandable-row" onclick="toggleDetails('{row_id}')" style="cursor: pointer;">
                                    <td><strong>{event_type}</strong> <span style="color: #999; font-size: 0.8em;">▼</span></td>
                                    <td style="text-align: center; color: #2e7d32; font-weight: bold;">{covered}</td>
                                    <td style="text-align: center; color: #c33; font-weight: bold;">{uncovered}</td>
                                    <td style="text-align: center; font-weight: bold;">{coverage_pct:.1f}%</td>
                                    <td>
                                        <div style="background: #eee; border-radius: 4px; overflow: hidden; height: 20px; min-width: 150px;">
                                            <div style="background: {bar_color}; width: {coverage_pct}%; height: 100%; display: flex; align-items: center; justify-content: flex-end; padding-right: 5px; color: white; font-size: 0.75em; font-weight: bold; min-width: 30px;">
                                                {coverage_pct:.0f}%
                                            </div>
                                        </div>
                                    </td>
                                    <td style="text-align: center;">{status_badge}</td>
                                    <td>{hv_cell}</td>
                                </tr>
                                <tr id="{row_id}" class="details-row" style="display: none;">
                                    <td colspan="7" style="background: #fafafa; padding: 20px;">
                                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                                            <div>
                                                <strong style="color: #2e7d32;">✅ Covered Product Events ({covered}):</strong>
                                                <div style="max-height: 150px; overflow-y: auto; margin-top: 10px; padding: 10px; background: white; border-radius: 4px; border: 1px solid #e0e0e0;">
                                                    {', '.join([f'<code style="background: #e8f5e9; padding: 2px 6px; border-radius: 3px; margin: 2px; display: inline-block;">{ce}</code>' for ce in covered_events[:50]]) if covered_events else '<em style="color: #999;">None</em>'}
                                                    {'<br><em style="color: #666;">... and ' + str(len(covered_events) - 50) + ' more</em>' if len(covered_events) > 50 else ''}
                                                </div>
                                            </div>
                                            <div>
                                                <strong style="color: #c33;">❌ Uncovered Product Events ({uncovered}):</strong>
                                                <div style="max-height: 150px; overflow-y: auto; margin-top: 10px; padding: 10px; background: white; border-radius: 4px; border: 1px solid #e0e0e0;">
                                                    {', '.join([f'<code style="background: #ffebee; padding: 2px 6px; border-radius: 3px; margin: 2px; display: inline-block;">{ue}</code>' for ue in uncovered_events[:50]]) if uncovered_events else '<em style="color: #999;">None - fully covered!</em>'}
                                                    {'<br><em style="color: #666;">... and ' + str(len(uncovered_events) - 50) + ' more</em>' if len(uncovered_events) > 50 else ''}
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
"""
        
        html += """                            </tbody>
                        </table>
                    </div>
                </div>
"""
    
    html += """            </div>
"""
    return html


def get_detection_rules_section(detection_rules):
    """Generate HTML for detection rules table with horizontal scrolling - v3.0 format"""
    if not detection_rules:
        return ""
    
    # Group rules by state for summary
    state_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    for rule in detection_rules:
        state_counts[rule.get('rule_state', 'Unknown')] += 1
        severity_counts[rule.get('rule_severity', 'Unknown')] += 1
    
    # Build state/severity summary
    state_summary = ' | '.join([f"{state}: {count}" for state, count in sorted(state_counts.items())])
    severity_summary = ' | '.join([f"{sev}: {count}" for sev, count in sorted(severity_counts.items())])
    
    html = f"""            <div class="section">
                <h2>🚨 Detection Rules Coverage</h2>
                <p style="color: #666; font-size: 0.95em; margin-bottom: 10px;">
                    These detection rules are monitoring for the following event combinations in your environment.
                </p>
                <div class="rule-summary">
                    <div class="summary-row"><strong>By State:</strong> {state_summary}</div>
                    <div class="summary-row"><strong>By Severity:</strong> {severity_summary}</div>
                </div>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Rule Name</th>
                                <th>Description</th>
                                <th>Severity</th>
                                <th>State</th>
                                <th>Type</th>
                                <th>Log Type</th>
                                <th>Product Event</th>
                                <th>Event Types</th>
                            </tr>
                        </thead>
                        <tbody>
"""
    
    for rule in sorted(detection_rules, key=lambda x: x['rule_name']):
        rule_name = rule.get('rule_name', 'Unknown')
        rule_desc = rule.get('rule_description', '')
        rule_severity = rule.get('rule_severity', '')
        rule_state = rule.get('rule_state', '')
        rule_type = rule.get('rule_type', '')
        log_type = rule.get('log_type', '').upper()
        product_event = rule.get('product_event', '')
        event_types = rule.get('event_types', [])
        
        # Format event types as comma-separated list or badge
        if event_types:
            event_types_display = ', '.join([et.upper() for et in event_types[:5]])
            if len(event_types) > 5:
                event_types_display += f' <span class="more-badge">+{len(event_types)-5} more</span>'
        else:
            event_types_display = '<em style="color:#999;">N/A</em>'
        
        severity_badge = get_severity_badge(rule_severity)
        state_badge = get_state_badge(rule_state)
        
        html += f"""                            <tr>
                                <td><strong>{rule_name}</strong></td>
                                <td class="desc-cell" title="{rule_desc}">{rule_desc}</td>
                                <td>{severity_badge}</td>
                                <td>{state_badge}</td>
                                <td>{rule_type}</td>
                                <td>{log_type}</td>
                                <td><code>{product_event}</code></td>
                                <td>{event_types_display}</td>
                            </tr>
"""
    
    html += """                        </tbody>
                    </table>
                </div>
            </div>
"""
    return html


def get_log_volume_section(log_volume_data, date_range_str=None):
    """Generate HTML for log volume data with horizontal scrolling"""
    if not log_volume_data:
        return ""
    
    log_type_volumes = {}
    for record in log_volume_data:
        log_type = record.get('log_type', 'Unknown').upper()
        try:
            event_count = int(record.get('event_count', 0))
            week_gb = float(record.get('week_gigabytes', 0))
        except (ValueError, TypeError):
            event_count = 0
            week_gb = 0.0
        
        if log_type not in log_type_volumes:
            log_type_volumes[log_type] = {'event_count': 0, 'week_gb': 0.0}
        
        log_type_volumes[log_type]['event_count'] += event_count
        log_type_volumes[log_type]['week_gb'] += week_gb
    
    sorted_types = sorted(log_type_volumes.items(), key=lambda x: x[1]['week_gb'], reverse=True)
    max_volume = max([v['week_gb'] for k, v in sorted_types], default=1)
    
    date_info = f'<p style="color: #667eea; font-size: 0.9em; margin-bottom: 15px; font-weight: bold;">📅 Data Period: {date_range_str}</p>' if date_range_str else ""
    
    html = f"""            <div class="section">
                <h2>📊 Top Log Types by Volume</h2>
                {date_info}
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Log Type</th>
                                <th>Weekly Events</th>
                                <th>Weekly Volume (GB)</th>
                                <th>Volume Comparison</th>
                            </tr>
                        </thead>
                        <tbody>
"""
    
    for log_type, data in sorted_types[:20]:
        event_count = data['event_count']
        week_gb = data['week_gb']
        bar_width = (week_gb / max_volume * 100) if max_volume > 0 else 0
        
        html += f"""                            <tr>
                                <td><strong>{log_type}</strong></td>
                                <td style="text-align: right;">{event_count:,}</td>
                                <td style="text-align: right;">{week_gb:.2f} GB</td>
                                <td><div style="background: #eee; border-radius: 4px; overflow: hidden; height: 20px; min-width: 100px;"><div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); width: {bar_width}%; height: 100%; display: flex; align-items: center; justify-content: flex-end; padding-right: 5px; color: white; font-size: 0.8em; font-weight: bold;">{bar_width:.0f}%</div></div></td>
                            </tr>
"""
    
    html += """                        </tbody>
                    </table>
                </div>
            </div>
"""
    return html


def determine_status_and_reason(event_type, product_event):
    """
    Determine status and reason for unmapped event.
    Returns (status, reason)
    """
    # Event types that typically warrant "Review Needed" status
    REVIEW_NEEDED_PATTERNS = [
        'user_login', 'user_logout', 'authentication', 'auth_',
        'process_launch', 'process_', 'file_creation', 'file_modification',
        'network_connection', 'network_', 'dns_', 'http_',
        'registry_', 'service_', 'scheduled_task',
        'resource_creation', 'resource_deletion', 'resource_read',
        'group_', 'user_creation', 'user_change',
        'email_', 'scan_', 'status_'
    ]
    
    # Product events that typically have existing detection rules
    REVIEW_NEEDED_PRODUCTS = [
        'assumerole', 'getobject', 'putobject', 'deleteobject',
        'createuser', 'deleteuser', 'attachpolicy', 'detachpolicy',
        'createbucket', 'deletebucket', 'putbucketpolicy',
        'authorizesg', 'revokesecurity', 'createkey', 'decrypt',
        'consolelogin', 'switchrole', 'createloginprofile',
        'runinstances', 'terminateinstances', 'stopinstances',
        'describe', 'list', 'get'
    ]
    
    event_lower = event_type.lower()
    product_lower = product_event.lower()
    
    # Check event patterns
    for pattern in REVIEW_NEEDED_PATTERNS:
        if pattern in event_lower:
            return 'review_needed', f'Event type matches common detectable pattern: "{pattern}"'
    
    # Check product patterns
    for pattern in REVIEW_NEEDED_PRODUCTS:
        if pattern in product_lower:
            return 'review_needed', f'Product event matches common cloud action: "{pattern}"'
    
    # Default to unmapped
    return 'unmapped', 'Does not match common detection patterns - may be specialized or low-risk event'


def get_unmapped_section(grouped):
    """Generate HTML for unmapped events with horizontal scrolling"""
    
    html = ""
    for log_type in sorted(grouped.keys()):
        events = grouped[log_type]
        
        # Count statuses for this log type
        unmapped_count = 0
        review_count = 0
        for event_type, product_event_type in events:
            status, _ = determine_status_and_reason(event_type, product_event_type)
            if status == 'review_needed':
                review_count += 1
            else:
                unmapped_count += 1
        
        status_summary = []
        if unmapped_count > 0:
            status_summary.append(f'{unmapped_count} unmapped')
        if review_count > 0:
            status_summary.append(f'{review_count} review needed')
        status_text = ' | '.join(status_summary)
        
        html += f"""        <div class="log-type-section">
            <h3>{log_type.upper()} <span class="log-type-count">{len(events)} events</span> <span style="font-size: 0.8em; color: #666; font-weight: normal;">({status_text})</span></h3>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Event Type</th>
                            <th>Product Event Type</th>
                            <th>Status</th>
                            <th>Why Gap Exists</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        
        for event_type, product_event_type in sorted(events):
            status, reason = determine_status_and_reason(event_type, product_event_type)
            
            if status == 'review_needed':
                status_badge = '<span class="status-badge status-review">Review Needed</span>'
                recommendation = f'Search rule library for keywords: "{event_type}" or "{product_event_type}"'
            else:
                status_badge = '<span class="status-badge status-unmapped">Unmapped</span>'
                recommendation = 'Evaluate security impact and create new detection rule if needed'
            
            html += f"""                        <tr>
                            <td><strong>{event_type.upper()}</strong></td>
                            <td><code>{product_event_type}</code></td>
                            <td>{status_badge}</td>
                            <td style="font-size: 0.9em; color: #666;">{reason}</td>
                            <td style="font-size: 0.9em; color: #666;">{recommendation}</td>
                        </tr>
"""
        
        html += """                    </tbody>
                </table>
            </div>
        </div>
"""
    return html


def generate_html_report(detection_rules, mapped, unmapped, log_volume_data=None):
    """Generate comprehensive HTML report with fast PDF export via html2pdf - v3.0"""
    total = len(mapped) + len(unmapped)
    coverage = (len(mapped) / total * 100) if total > 0 else 0
    
    unmapped_list = sorted(list(unmapped))
    grouped = group_by_logtype(unmapped_list)
    
    date_range_str = None
    if log_volume_data:
        date_range_str, _ = calculate_data_timespan(log_volume_data)
    
    detection_rules_section = get_detection_rules_section(detection_rules)
    log_volume_section = ""
    if log_volume_data:
        log_volume_section = get_log_volume_section(log_volume_data, date_range_str)
    
    # Generate coverage gap analysis
    coverage_analysis = analyze_coverage_gaps(mapped, unmapped)
    coverage_gap_section = get_coverage_gap_section(coverage_analysis)
    
    data_period_header = f'<div class="timestamp" style="margin-top: 8px;">📅 Data Period: {date_range_str}</div>' if date_range_str else ""
    
    # Calculate rule stats
    unique_rules = len(set(r['rule_name'] for r in detection_rules))
    total_event_types = sum(r.get('event_type_count', 0) for r in detection_rules)
    
    # Categorize unmapped events
    unmapped_only_count, review_needed_count = categorize_unmapped_events(unmapped)
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YARAL Event Mapping Report v3.0</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; padding: 20px; min-height: 100vh; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); overflow: hidden; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        header p {{ font-size: 1.1em; opacity: 0.9; }}
        .version-badge {{ background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 20px; font-size: 0.8em; margin-left: 10px; }}
        .timestamp {{ font-size: 0.9em; opacity: 0.8; margin-top: 10px; }}
        .button-group {{ display: flex; gap: 10px; justify-content: center; margin-top: 15px; }}
        .download-btn {{ background: #f5576c; color: white; padding: 12px 24px; border: none; border-radius: 5px; font-size: 1em; font-weight: bold; cursor: pointer; display: inline-block; transition: background 0.3s; }}
        .download-btn:hover {{ background: #d32f2f; }}
        .download-btn:active {{ transform: scale(0.98); }}
        .content {{ padding: 40px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .summary-card {{ background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); padding: 25px; border-radius: 8px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .summary-card.total {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
        .summary-card.unmapped {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }}
        .summary-card.mapped {{ background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; }}
        .summary-card.rules {{ background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; }}
        .summary-card.review {{ background: linear-gradient(135deg, #ff9a56 0%, #ff6b35 100%); color: white; }}
        .summary-card h3 {{ font-size: 0.85em; opacity: 0.9; margin-bottom: 10px; text-transform: uppercase; }}
        .summary-card .number {{ font-size: 2.2em; font-weight: bold; }}
        .summary-card .percentage {{ font-size: 1.8em; font-weight: bold; margin-top: 5px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ font-size: 1.8em; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 3px solid #667eea; color: #333; }}
        .rule-summary {{ background: #f8f9fa; padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9em; }}
        .rule-summary .summary-row {{ margin: 5px 0; }}
        .log-type-section {{ margin-bottom: 30px; background: #f8f9fa; border-left: 4px solid #667eea; padding: 20px; border-radius: 5px; }}
        .log-type-section h3 {{ color: #667eea; margin-bottom: 15px; font-size: 1.3em; }}
        .log-type-count {{ background: white; padding: 5px 10px; border-radius: 20px; font-size: 0.9em; color: #667eea; font-weight: bold; display: inline-block; margin-left: 10px; }}
        .table-wrapper {{ overflow-x: auto; -webkit-overflow-scrolling: touch; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }}
        table {{ width: 100%; border-collapse: collapse; background: white; min-width: 1000px; }}
        thead {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
        th {{ padding: 15px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 0.85em; white-space: nowrap; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #eee; }}
        td.desc-cell {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.9em; color: #666; }}
        tbody tr:hover {{ background: #f8f9fa; }}
        .status-badge {{ display: inline-block; padding: 5px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }}
        .status-unmapped {{ background: #ffe5e5; color: #c33; }}
        .status-review {{ background: #fff3e0; color: #e65100; }}
        .severity-badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }}
        .severity-high {{ background: #ffebee; color: #c62828; }}
        .severity-medium {{ background: #fff3e0; color: #ef6c00; }}
        .severity-low {{ background: #e8f5e9; color: #2e7d32; }}
        .state-badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }}
        .state-active {{ background: #e8f5e9; color: #2e7d32; }}
        .state-inactive {{ background: #fafafa; color: #757575; }}
        .more-badge {{ background: #667eea; color: white; padding: 2px 6px; border-radius: 10px; font-size: 0.75em; margin-left: 5px; }}
        .coverage-status {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }}
        .coverage-complete {{ background: #e8f5e9; color: #2e7d32; }}
        .coverage-good {{ background: #e8f5e9; color: #388e3c; }}
        .coverage-gap {{ background: #fff3e0; color: #e65100; }}
        .coverage-none {{ background: #ffebee; color: #c62828; }}
        .high-value-flag {{ color: #c62828; font-weight: bold; }}
        .high-value-code {{ background: #ffebee; color: #c62828; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }}
        .expandable-row:hover {{ background: #f0f4ff !important; }}
        .details-row td {{ border-top: none !important; }}
        .coverage-table {{ min-width: 900px; }}
        .footer {{ background: #f8f9fa; padding: 20px 40px; text-align: center; color: #666; font-size: 0.9em; }}
        .coverage-bar {{ background: #eee; height: 30px; border-radius: 15px; overflow: hidden; margin-top: 10px; }}
        .coverage-fill {{ background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%); height: 100%; width: {coverage}%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 0.9em; }}
        .no-results {{ text-align: center; padding: 40px; color: #666; font-size: 1.1em; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }}
        @media print {{ body {{ background: white; }} .button-group {{ display: none; }} .table-wrapper {{ overflow-x: visible; }} }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 YARAL Event Mapping Analysis Report <span class="version-badge">v{VERSION}</span></h1>
            <p>Detection Coverage Analysis - Rule-Based Event Mappings</p>
            <div class="timestamp">Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</div>
            {data_period_header}
            <div class="button-group">
                <button class="download-btn" onclick="downloadPDF()">📥 Download as PDF</button>
                <button class="download-btn" onclick="window.print()" style="background: #667eea;">🖨️ Print</button>
            </div>
        </header>
        
        <div class="content">
            <div class="summary">
                <div class="summary-card rules">
                    <h3>Unique Rules</h3>
                    <div class="number">{unique_rules}</div>
                </div>
                <div class="summary-card mapped">
                    <h3>Mapped Events</h3>
                    <div class="number">{len(mapped)}</div>
                </div>
                <div class="summary-card unmapped">
                    <h3>Unmapped</h3>
                    <div class="number">{unmapped_only_count}</div>
                </div>
                <div class="summary-card review">
                    <h3>Review Needed</h3>
                    <div class="number">{review_needed_count}</div>
                </div>
                <div class="summary-card total">
                    <h3>Detection Coverage</h3>
                    <div class="percentage">{coverage:.1f}%</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Coverage Overview</h2>
                <div class="coverage-bar">
                    <div class="coverage-fill">{coverage:.1f}% Covered</div>
                </div>
            </div>
            
            {detection_rules_section}
            {coverage_gap_section}
            {log_volume_section}
            
            <div class="section">
                <h2>📋 Detailed Unmapped Events</h2>
                <p style="color: #666; margin-bottom: 15px;">Complete list of event combinations not covered by any detection rule. Use the Coverage Gap Analysis above for prioritization.</p>
                <div class="status-legend" style="display: flex; gap: 20px; margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <div><span class="status-badge status-unmapped">Unmapped</span> No detection rule currently covers this event</div>
                    <div><span class="status-badge status-review">Review Needed</span> Check against existing rule library for potential coverage</div>
                </div>
                {get_unmapped_section(grouped) if unmapped else '<div class="no-results">✓ All events are mapped to detection rules!</div>'}
            </div>
        </div>
        
        <div class="footer">
            <p>YARAL Event Mapping Comparison Tool v{VERSION} | <a href="https://github.com/steady-mongoose/Google_SecOps-Audit" target="_blank">GitHub Repository</a></p>
            <p style="margin-top: 5px; font-size: 0.85em; color: #999;">This report shows detection rules and event combinations in your environment.</p>
        </div>
    </div>

    <script>
        function toggleDetails(rowId) {{
            const row = document.getElementById(rowId);
            if (row.style.display === 'none') {{
                row.style.display = 'table-row';
            }} else {{
                row.style.display = 'none';
            }}
        }}
        
        function downloadPDF() {{
            const element = document.querySelector('.container');
            const opt = {{
                margin: 10,
                filename: 'yaral_event_mapping_report_v3.3.pdf',
                image: {{ type: 'jpeg', quality: 0.98 }},
                html2canvas: {{ scale: 2 }},
                jsPDF: {{ orientation: 'landscape', unit: 'mm', format: 'a4' }}
            }};
            
            // Show progress
            const btn = event.target;
            btn.textContent = '⏳ Generating PDF...';
            btn.disabled = true;
            
            html2pdf().set(opt).from(element).save().then(() => {{
                btn.textContent = '📥 Download as PDF';
                btn.disabled = false;
            }}).catch(() => {{
                btn.textContent = '📥 Download as PDF';
                btn.disabled = false;
            }});
        }}
    </script>
</body>
</html>
"""
    return html


def save_html_report(html_content):
    """Save HTML report to file"""
    output_dir = Path.home() / "Downloads"
    try:
        report_file = output_dir / f"yaral_event_mapping_report_v{VERSION}.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print("\n✓ HTML report saved to:")
        print(f"  {report_file}")
        return str(report_file)
    except Exception as e:
        print(f"✗ Error saving report: {e}")
        return None


def main():
    """Main execution function"""
    print("="*80)
    print(f"YARAL Event Mapping Comparison Tool - v{VERSION}")
    print("="*80)
    print("\nNEW in v3.3:")
    print("  ✅ Added 'Why Gap Exists' column to explain reasons for unmapped events")
    print("  ✅ More specific recommendations based on matched patterns")
    print("  ✅ Refined categorization for better accuracy in comparisons")
    print("="*80 + "\n")
    
    root = tk.Tk()
    root.withdraw()
    
    print("Please select Detection Results CSV file...")
    print("  (From your new YARAL query with rule_name, rule_description, etc.)")
    detection_file = filedialog.askopenfilename(
        title="Select Detection Results CSV (v3.0 format)",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        initialdir=str(Path.home() / "Downloads")
    )
    
    if not detection_file:
        print("✗ No detection file selected. Exiting.")
        root.destroy()
        return
    
    print(f"✓ Selected: {Path(detection_file).name}\n")
    
    print("Please select Event Results CSV file...")
    event_file = filedialog.askopenfilename(
        title="Select Event Results CSV",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        initialdir=str(Path.home() / "Downloads")
    )
    
    if not event_file:
        print("✗ No event file selected. Exiting.")
        root.destroy()
        return
    
    print(f"✓ Selected: {Path(event_file).name}\n")
    
    print("Please select Log Volume CSV file (OPTIONAL)...")
    log_volume_file = filedialog.askopenfilename(
        title="Select Log Volume CSV (optional)",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        initialdir=str(Path.home() / "Downloads")
    )
    
    if log_volume_file:
        print(f"✓ Selected: {Path(log_volume_file).name}\n")
    else:
        print("⊘ Skipped log volume file (optional)\n")
    
    root.destroy()
    
    print("Processing files...")
    print("\nLoading detection rules (v3.0 format)...")
    detection_rules, detection_tuples = load_detection_rules_v3(detection_file)
    
    print("\nLoading event results...")
    event_tuples = load_event_results(event_file)
    
    log_volume_data = []
    if log_volume_file:
        print("\nLoading log volume data...")
        log_volume_data = load_log_volume_data(log_volume_file)
    
    if not detection_rules or not event_tuples:
        print("\n✗ Failed to load files. Exiting.")
        return
    
    print("\nComparing results...\n")
    mapped, unmapped = compare_results(detection_tuples, event_tuples)
    
    total = len(mapped) + len(unmapped)
    coverage = (len(mapped) / total * 100) if total > 0 else 0
    
    # Calculate unique rules
    unique_rules = len(set(r['rule_name'] for r in detection_rules))
    
    # Categorize unmapped
    unmapped_only_count, review_needed_count = categorize_unmapped_events(unmapped)
    
    print(f"\n{'='*80}")
    print("SUMMARY STATISTICS")
    print(f"{'='*80}")
    print(f"Detection rule records loaded: {len(detection_rules)}")
    print(f"Unique rule names: {unique_rules}")
    print(f"Coverage tuples generated: {len(detection_tuples)}")
    print(f"Total unique event combinations: {total}")
    print(f"Mapped to rules: {len(mapped)}")
    print(f"NOT mapped to rules: {len(unmapped)}")
    print(f"Unmapped only: {unmapped_only_count}")
    print(f"Review needed: {review_needed_count}")
    if len(unmapped) != (unmapped_only_count + review_needed_count):
        print("⚠️ Warning: Categorization count mismatch!")
    print(f"Coverage: {coverage:.1f}%")
    if log_volume_data:
        date_range, weeks = calculate_data_timespan(log_volume_data)
        if date_range:
            print(f"Data period: {date_range}")
    print(f"{'='*80}\n")
    
    print("Generating HTML report...")
    html_content = generate_html_report(detection_rules, mapped, unmapped, log_volume_data if log_volume_data else None)
    report_path = save_html_report(html_content)
    
    if report_path:
        print("\n✓ Report generated successfully!")
        print("✓ Opening report in default browser...")
        print(f"\n💡 NEW in v{VERSION}:")
        print("   ✅ 'Why Gap Exists' explanations")
        print("   ✅ Specific recommendations")
        print("   ✅ Improved accuracy in gap categorization")
        webbrowser.open(f'file:///{report_path}')
        
        print(f"\n{'='*80}")
        print("Done! The HTML report has been opened in your browser.")
        print(f"{'='*80}")
    else:
        print("✗ Failed to generate report.")


if __name__ == "__main__":
    main()
