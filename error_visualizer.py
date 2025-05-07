#!/usr/bin/env python3
import re
import sys
import os
from collections import defaultdict
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.ticker import MaxNLocator

def extract_error_patterns(log_file):
    """Extract error patterns with timestamps from log file."""
    if not os.path.exists(log_file):
        print(f"Error: File {log_file} not found")
        return None, None
    
    # Regular expressions
    log_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (ERROR) - (.*)')
    
    # Patterns for categorization (ordered by priority)
    error_categories = [
        ("SPANNER_MUTATION_LIMIT", r"too many mutations|Maximum number"),
        ("PROCESS_TERMINATED", r"process.*terminated|process pool"),
        ("TABLE_ERRORS", r"Failed batch details.*Tables attempted"),
        ("DATA_FORMAT", r"'str' object|'dict' object|TypeError|ValueError|KeyError"),
        ("COMMIT_FAILED", r"commit FAILED|transaction.*failed"),
        ("OTHER", r".*")  # Catch-all
    ]
    
    # Compile regex patterns
    compiled_categories = [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in error_categories]
    
    # Store error data
    errors_by_category = defaultdict(list)
    error_messages = defaultdict(list)
    
    # Process the log file
    with open(log_file, 'r', errors='replace') as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                timestamp_str, _, message = match.groups()
                
                # Parse timestamp
                try:
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
                
                # Categorize the error
                category = "OTHER"
                for cat_name, pattern in compiled_categories:
                    if pattern.search(message):
                        category = cat_name
                        break
                
                # Add to category list
                errors_by_category[category].append(timestamp)
                
                # Store abbreviated message
                short_msg = message[:100] + "..." if len(message) > 100 else message
                error_messages[timestamp].append((category, short_msg))
    
    return errors_by_category, error_messages

def create_error_timeline(errors_by_category, error_messages=None, output_file="error_timeline.png"):
    """Create error timeline visualization."""
    if not errors_by_category:
        print("No error data to visualize")
        return
    
    # Setup plot
    plt.figure(figsize=(15, 8))
    
    # Colors for categories
    colors = {
        "SPANNER_MUTATION_LIMIT": "red",
        "PROCESS_TERMINATED": "orange",
        "TABLE_ERRORS": "purple",
        "DATA_FORMAT": "blue",
        "COMMIT_FAILED": "brown",
        "OTHER": "gray"
    }
    
    # Sort categories by first occurrence
    first_occurrence = {cat: min(timestamps) for cat, timestamps in errors_by_category.items() if timestamps}
    sorted_categories = sorted(first_occurrence.keys(), key=lambda x: first_occurrence[x])
    
    # Calculate y positions
    y_positions = {cat: i for i, cat in enumerate(sorted_categories)}
    
    # Plot each error category
    for category, timestamps in errors_by_category.items():
        if not timestamps:
            continue
            
        y = y_positions[category]
        plt.scatter(timestamps, [y] * len(timestamps), 
                  label=f"{category} ({len(timestamps)})", 
                  s=50, color=colors.get(category, 'black'), alpha=0.7)
    
    # Add category labels on y-axis
    plt.yticks(list(y_positions.values()), list(y_positions.keys()))
    
    # Format x-axis to show time
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.gca().xaxis.set_major_locator(MaxNLocator(20))  # Adjust number of ticks
    plt.gcf().autofmt_xdate()
    
    # Add grid for better readability
    plt.grid(axis='x', linestyle='--', alpha=0.7)
    
    # Add labels and title
    plt.xlabel('Time')
    plt.title('Error Timeline by Category')
    plt.tight_layout()
    
    # Add legend
    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.15), ncol=3)
    
    # Save figure
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Error timeline saved to {output_file}")
    
    # Create detailed textual timeline
    if error_messages:
        with open("detailed_error_timeline.txt", "w") as f:
            f.write("DETAILED ERROR TIMELINE\n")
            f.write("=====================\n\n")
            
            # Group messages by minute for readability
            by_minute = defaultdict(list)
            for timestamp, messages in error_messages.items():
                minute_bucket = timestamp.replace(second=0)
                by_minute[minute_bucket].extend(messages)
            
            # Print messages by minute
            for minute, messages in sorted(by_minute.items()):
                f.write(f"\n=== {minute.strftime('%Y-%m-%d %H:%M')} ===\n")
                f.write(f"Total errors in minute: {len(messages)}\n\n")
                
                # Group by category within minute
                by_category = defaultdict(list)
                for category, msg in messages:
                    by_category[category].append(msg)
                
                # Print each category
                for category, msgs in sorted(by_category.items()):
                    f.write(f"{category} ({len(msgs)}):\n")
                    
                    # Get unique messages with counts
                    unique_msgs = defaultdict(int)
                    for msg in msgs:
                        unique_msgs[msg] += 1
                    
                    # Print top unique messages
                    for msg, count in sorted(unique_msgs.items(), key=lambda x: x[1], reverse=True):
                        if count > 1:
                            f.write(f"  [{count}x] {msg}\n")
                        else:
                            f.write(f"  {msg}\n")
                    f.write("\n")
        
        print(f"Detailed error timeline saved to detailed_error_timeline.txt")

def generate_summary_report(log_file, errors_by_category):
    """Generate a summary report of the log analysis."""
    if not errors_by_category:
        return
        
    # Get earliest and latest error timestamps
    all_timestamps = []
    for timestamps in errors_by_category.values():
        all_timestamps.extend(timestamps)
    
    if not all_timestamps:
        return
        
    earliest = min(all_timestamps)
    latest = max(all_timestamps)
    duration = latest - earliest
    
    # Count total errors
    total_errors = sum(len(timestamps) for timestamps in errors_by_category.values())
    
    # Calculate error rates
    if duration.total_seconds() > 0:
        errors_per_minute = total_errors / (duration.total_seconds() / 60)
    else:
        errors_per_minute = 0
    
    # Calculate category percentages
    category_percentages = {cat: (len(timestamps) / total_errors * 100) 
                           for cat, timestamps in errors_by_category.items() if timestamps}
    
    # Generate report
    with open("error_summary_report.txt", "w") as f:
        f.write("ERROR SUMMARY REPORT\n")
        f.write("===================\n\n")
        
        f.write(f"Log file: {log_file}\n")
        f.write(f"Analysis timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("ERROR STATISTICS\n")
        f.write("-----------------\n")
        f.write(f"Total errors: {total_errors}\n")
        f.write(f"Error timespan: {earliest.strftime('%H:%M:%S')} to {latest.strftime('%H:%M:%S')} ({duration})\n")
        f.write(f"Error rate: {errors_per_minute:.2f} errors/minute\n\n")
        
        f.write("ERROR CATEGORIES\n")
        f.write("-----------------\n")
        for category, percentage in sorted(category_percentages.items(), key=lambda x: x[1], reverse=True):
            count = len(errors_by_category[category])
            f.write(f"{category}: {count} errors ({percentage:.1f}%)\n")
        
        f.write("\nTIME DISTRIBUTION\n")
        f.write("-----------------\n")
        
        # Group by 10-minute buckets
        time_buckets = defaultdict(int)
        for timestamps in errors_by_category.values():
            for timestamp in timestamps:
                bucket = timestamp.replace(minute=(timestamp.minute // 10) * 10, second=0)
                time_buckets[bucket] += 1
        
        for bucket in sorted(time_buckets.keys()):
            f.write(f"{bucket.strftime('%H:%M')} - {time_buckets[bucket]} errors ({time_buckets[bucket]/total_errors*100:.1f}%)\n")
    
    print(f"Summary report saved to error_summary_report.txt")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python error_visualizer.py <log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    errors_by_category, error_messages = extract_error_patterns(log_file)
    
    if errors_by_category:
        create_error_timeline(errors_by_category, error_messages)
        generate_summary_report(log_file, errors_by_category)
        print("Error analysis complete.")
    else:
        print("No errors found in log file.")