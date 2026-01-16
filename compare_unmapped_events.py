#!/usr/bin/env python3
"""
YARAL Event Mapping Comparison Tool - v2.4 (Optimized PDF Export)
Shows detection rules from CSV + coverage analysis + fast PDF export
With client-side PDF generation for instant downloads
"""

import csv
import tkinter as tk
from tkinter import filedialog
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import webbrowser


def get_column_value(row, *possible_names):
    """Try to get a column value from multiple possible column names"""
    for name in possible_names:
        if name in row and row[name]:
            return row[name].strip()
    return ""


def load_detection_rules(file_path):
    """Load detection rules from CSV - returns list of rule dicts"""
    detection_rules = []
    detection_tuples = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            print(f"  Column names found: {reader.fieldnames}")
            
            row_count = 0
            for row in reader:
                row_count += 1
                
                # Handle different possible column names
                rule_name = get_column_value(row, 'Rulename', 'rule_name', 'Rule Name', 'RuleName')
                log_type = get_column_value(row, 'Logtype', 'log_type', 'Log Type', 'LOG_TYPE').lower()
                event_type = get_column_value(row, 'Eventtype', 'event_type', 'Event Type', 'EVENT_TYPE').lower()
                product_event_type = get_column_value(row, 'Productevent', 'product_event_type', 'Product Event Type')
                day = get_column_value(row, 'Day', 'day', 'Date')
                event_count = get_column_value(row, 'event_count', 'Event Count')
                trigger_count = get_column_value(row, 'trigger_count', 'Trigger Count', 'alert_count')
                estimated_gb = get_column_value(row, 'estimated_gb_per_day', 'estimated_daily_gb', 'Daily GB')
                
                if rule_name:
                    detection_rules.append({
                        'rule_name': rule_name,
                        'log_type': log_type,
                        'event_type': event_type,
                        'product_event_type': product_event_type,
                        'day': day,
                        'event_count': event_count,
                        'trigger_count': trigger_count,
                        'estimated_gb': estimated_gb
                    })
                    
                    if log_type and event_type and product_event_type and event_type != "eventtype_unspecified":
                        detection_tuples.add((log_type, event_type, product_event_type))
            
            print(f"  Processed {row_count} rows")
            print(f"✓ Loaded {len(detection_rules)} detection rules")
            return detection_rules, detection_tuples
    
    except Exception as e:
        print(f"✗ Error loading detection file: {e}")
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
                product_event_type = get_column_value(row, 'product_event_type', 'Productevent', 'productevent', 'ProductEvent', 'PRODUCT_EVENT_TYPE')
                
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
    """Find unmapped combinations"""
    unmapped = event_tuples - detection_tuples
    mapped = event_tuples & detection_tuples
    return mapped, unmapped


def group_by_logtype(unmapped):
    """Group unmapped events by log type"""
    grouped = defaultdict(list)
    for log_type, event_type, product_event_type in unmapped:
        grouped[log_type].append((event_type, product_event_type))
    return grouped


def get_detection_rules_section(detection_rules):
    """Generate HTML for detection rules table with horizontal scrolling"""
    if not detection_rules:
        return ""
    
    html = """            <div class="section">
                <h2>🚨 Detection Rules Coverage</h2>
                <p style="color: #666; font-size: 0.95em; margin-bottom: 20px;">
                    These detection rules are monitoring for the following event combinations in your environment.
                </p>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Rule Name</th>
                                <th>Log Type</th>
                                <th>Event Type</th>
                                <th>Product Event</th>
                                <th>Triggers</th>
                                <th>Est. GB/Day</th>
                            </tr>
                        </thead>
                        <tbody>
"""
    
    for rule in detection_rules:
        rule_name = rule.get('rule_name', 'Unknown')
        log_type = rule.get('log_type', '').upper()
        event_type = rule.get('event_type', '').upper()
        product_event = rule.get('product_event_type', '')
        trigger_count = rule.get('trigger_count', '0')
        estimated_gb = rule.get('estimated_gb', '0')
        
        html += f"""                            <tr>
                                <td><strong>{rule_name}</strong></td>
                                <td>{log_type}</td>
                                <td>{event_type}</td>
                                <td><code>{product_event}</code></td>
                                <td style="text-align: center;"><strong>{trigger_count}</strong></td>
                                <td style="text-align: right;">{estimated_gb}</td>
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


def get_unmapped_section(grouped):
    """Generate HTML for unmapped events with horizontal scrolling"""
    html = ""
    for log_type in sorted(grouped.keys()):
        events = grouped[log_type]
        html += f"""        <div class="log-type-section">
            <h3>{log_type.upper()} <span class="log-type-count">{len(events)} events</span></h3>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Event Type</th>
                            <th>Product Event Type</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        
        for event_type, product_event_type in sorted(events):
            html += f"""                        <tr>
                            <td><strong>{event_type.upper()}</strong></td>
                            <td><code>{product_event_type}</code></td>
                            <td><span class="status-badge status-unmapped">Unmapped</span></td>
                        </tr>
"""
        
        html += """                    </tbody>
                </table>
            </div>
        </div>
"""
    return html


def generate_html_report(detection_rules, mapped, unmapped, log_volume_data=None):
    """Generate comprehensive HTML report with fast PDF export via html2pdf"""
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
    
    data_period_header = f'<div class="timestamp" style="margin-top: 8px;">📅 Data Period: {date_range_str}</div>' if date_range_str else ""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YARAL Event Mapping Report</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; padding: 20px; min-height: 100vh; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); overflow: hidden; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        header p {{ font-size: 1.1em; opacity: 0.9; }}
        .timestamp {{ font-size: 0.9em; opacity: 0.8; margin-top: 10px; }}
        .button-group {{ display: flex; gap: 10px; justify-content: center; margin-top: 15px; }}
        .download-btn {{ background: #f5576c; color: white; padding: 12px 24px; border: none; border-radius: 5px; font-size: 1em; font-weight: bold; cursor: pointer; display: inline-block; transition: background 0.3s; }}
        .download-btn:hover {{ background: #d32f2f; }}
        .download-btn:active {{ transform: scale(0.98); }}
        .content {{ padding: 40px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .summary-card {{ background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); padding: 25px; border-radius: 8px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .summary-card.total {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
        .summary-card.unmapped {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }}
        .summary-card.mapped {{ background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; }}
        .summary-card h3 {{ font-size: 0.9em; opacity: 0.9; margin-bottom: 10px; text-transform: uppercase; }}
        .summary-card .number {{ font-size: 2.5em; font-weight: bold; }}
        .summary-card .percentage {{ font-size: 1.8em; font-weight: bold; margin-top: 5px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ font-size: 1.8em; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 3px solid #667eea; color: #333; }}
        .log-type-section {{ margin-bottom: 30px; background: #f8f9fa; border-left: 4px solid #667eea; padding: 20px; border-radius: 5px; }}
        .log-type-section h3 {{ color: #667eea; margin-bottom: 15px; font-size: 1.3em; }}
        .log-type-count {{ background: white; padding: 5px 10px; border-radius: 20px; font-size: 0.9em; color: #667eea; font-weight: bold; display: inline-block; margin-left: 10px; }}
        .table-wrapper {{ overflow-x: auto; -webkit-overflow-scrolling: touch; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }}
        table {{ width: 100%; border-collapse: collapse; background: white; min-width: 800px; }}
        thead {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
        th {{ padding: 15px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 0.9em; white-space: nowrap; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #eee; }}
        tbody tr:hover {{ background: #f8f9fa; }}
        .status-badge {{ display: inline-block; padding: 5px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }}
        .status-unmapped {{ background: #ffe5e5; color: #c33; }}
        .footer {{ background: #f8f9fa; padding: 20px 40px; text-align: center; color: #666; font-size: 0.9em; }}
        .coverage-bar {{ background: #eee; height: 30px; border-radius: 15px; overflow: hidden; margin-top: 10px; }}
        .coverage-fill {{ background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%); height: 100%; width: {coverage}%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 0.9em; }}
        .no-results {{ text-align: center; padding: 40px; color: #666; font-size: 1.1em; }}
        @media print {{ body {{ background: white; }} .button-group {{ display: none; }} .table-wrapper {{ overflow-x: visible; }} }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 YARAL Event Mapping Analysis Report</h1>
            <p>Detection Coverage Analysis - Granular Rule Mappings</p>
            <div class="timestamp">Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</div>
            {data_period_header}
            <div class="button-group">
                <button class="download-btn" onclick="downloadPDF()">📥 Download as PDF</button>
                <button class="download-btn" onclick="window.print()" style="background: #667eea;">🖨️ Print</button>
            </div>
        </header>
        
        <div class="content">
            <div class="summary">
                <div class="summary-card total">
                    <h3>Active Rules</h3>
                    <div class="number">{len(detection_rules)}</div>
                </div>
                <div class="summary-card mapped">
                    <h3>Mapped Events</h3>
                    <div class="number">{len(mapped)}</div>
                </div>
                <div class="summary-card unmapped">
                    <h3>Unmapped Events</h3>
                    <div class="number">{len(unmapped)}</div>
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
            {log_volume_section}
            
            <div class="section">
                <h2>Unmapped Event Combinations</h2>
                {get_unmapped_section(grouped) if unmapped else '<div class="no-results">✓ All events are mapped to detection rules!</div>'}
            </div>
        </div>
        
        <div class="footer">
            <p>This report shows detection rules and event combinations in your environment.</p>
        </div>
    </div>

    <script>
        function downloadPDF() {{
            const element = document.querySelector('.container');
            const opt = {{
                margin: 10,
                filename: 'unmapped_events_report.pdf',
                image: {{ type: 'jpeg', quality: 0.98 }},
                html2canvas: {{ scale: 2 }},
                jsPDF: {{ orientation: 'portrait', unit: 'mm', format: 'a4' }}
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
        report_file = output_dir / "unmapped_events_report.html"
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
    print("YARAL Event Mapping Comparison Tool - v2.4 (Optimized PDF)")
    print("="*80 + "\n")
    
    root = tk.Tk()
    root.withdraw()
    
    print("Please select Detection Results CSV file...")
    detection_file = filedialog.askopenfilename(
        title="Select Detection Results CSV",
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
    print("\nLoading detection rules...")
    detection_rules, detection_tuples = load_detection_rules(detection_file)
    
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
    
    print(f"\n{'='*80}")
    print("SUMMARY STATISTICS")
    print(f"{'='*80}")
    print(f"Detection rules loaded: {len(detection_rules)}")
    print(f"Total unique event combinations: {total}")
    print(f"Mapped to rules: {len(mapped)}")
    print(f"NOT mapped to rules: {len(unmapped)}")
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
        print("\n💡 IMPROVEMENTS in v2.4:")
        print("   ✅ Fast PDF download (instant, no loading preview)")
        print("   ✅ Optimized with html2pdf.js library")
        print("   ✅ Additional Print button for browser printing")
        print("   ✅ Progress indicator while generating PDF")
        print("   ✅ Better performance for large datasets")
        webbrowser.open(f'file:///{report_path}')
        
        print(f"\n{'='*80}")
        print("Done! The HTML report has been opened in your browser.")
        print(f"{'='*80}")
    else:
        print("✗ Failed to generate report.")


if __name__ == "__main__":
    main()
