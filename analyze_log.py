#!/usr/bin/env python3
import re
import sys
import os
from collections import defaultdict, Counter
from datetime import datetime

def analyze_log(log_file):
    if not os.path.exists(log_file):
        print(f"Error: File {log_file} not found")
        return

    # Store pattern information
    patterns = defaultdict(lambda: {"count": 0, "level": "", "first_seen": None, "last_seen": None})
    
    # Store error times for distribution analysis
    error_times = []
    
    # Regular expressions
    log_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([A-Z]+) - (.*)')
    
    # Patterns to replace for normalization
    replacements = [
        (re.compile(r'\d+\.\d+s'), '<TIME>s'),
        (re.compile(r'\b\d+\b'), '<N>'),
        (re.compile(r'0x[0-9a-f]+'), '<ADDR>'),
        (re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), '<UUID>'),
        (re.compile(r'\/[\/\w\.\-]+\/[\w\.\-]+'), '<PATH>'),
        (re.compile(r'\d+\.\d+'), '<N>.<N>'),
    ]
    
    # Process the log file
    with open(log_file, 'r', errors='replace') as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                timestamp_str, level, message = match.groups()
                
                # Parse timestamp
                try:
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
                
                # For error distribution
                if level == "ERROR":
                    error_times.append(timestamp)
                
                # Normalize the message
                normalized_msg = message
                for pattern, replacement in replacements:
                    normalized_msg = pattern.sub(replacement, normalized_msg)
                
                # Update pattern stats
                if patterns[normalized_msg]["count"] == 0:
                    patterns[normalized_msg]["first_seen"] = timestamp
                    patterns[normalized_msg]["level"] = level
                else:
                    patterns[normalized_msg]["last_seen"] = timestamp
                
                patterns[normalized_msg]["count"] += 1
    
    # Generate general pattern report
    with open("log_patterns_report.txt", "w") as report:
        report.write("LOG PATTERN ANALYSIS\n")
        report.write("===================\n\n")
        
        # Overall statistics
        report.write(f"Total unique message patterns: {len(patterns)}\n")
        level_counts = Counter([info["level"] for info in patterns.values()])
        report.write("Message levels:\n")
        for level, count in level_counts.items():
            report.write(f"  {level}: {count} patterns\n")
        report.write("\n")
        
        # Top patterns by level
        for level in ["ERROR", "WARNING", "INFO", "DEBUG"]:
            if level in level_counts:
                report.write(f"TOP {level} PATTERNS\n")
                report.write("-" * 80 + "\n")
                
                level_patterns = [(pattern, info) for pattern, info in patterns.items() 
                                 if info["level"] == level]
                sorted_patterns = sorted(level_patterns, key=lambda x: x[1]["count"], reverse=True)
                
                for pattern, info in sorted_patterns[:10]:  # Top 10 per level
                    first = info["first_seen"].strftime('%Y-%m-%d %H:%M:%S')
                    last = info["last_seen"].strftime('%Y-%m-%d %H:%M:%S') if info["last_seen"] else first
                    report.write(f"Count: {info['count']}\n")
                    report.write(f"Time range: {first} to {last}\n")
                    report.write(f"Pattern: {pattern}\n\n")
        
        # Error time distribution (10-minute buckets)
        if error_times:
            report.write("ERROR TIME DISTRIBUTION\n")
            report.write("-" * 80 + "\n")
            
            # Group by 10-minute buckets
            time_buckets = defaultdict(int)
            for timestamp in error_times:
                bucket = timestamp.replace(minute=timestamp.minute - timestamp.minute % 10, second=0)
                time_buckets[bucket] += 1
            
            for bucket in sorted(time_buckets.keys()):
                report.write(f"{bucket.strftime('%Y-%m-%d %H:%M')} - {time_buckets[bucket]} errors\n")
    
    # Generate compressed log
    with open("compressed_log.txt", "w") as compressed:
        compressed.write("COMPRESSED LOG SUMMARY\n")
        compressed.write("=====================\n\n")
        
        # Sort patterns by first occurrence time
        sorted_by_time = sorted(patterns.items(), key=lambda x: x[1]["first_seen"])
        
        current_date = None
        for pattern, info in sorted_by_time:
            if info["count"] < 10:  # Skip very infrequent patterns
                continue
                
            pattern_date = info["first_seen"].date()
            
            # Add date headers
            if current_date != pattern_date:
                compressed.write(f"\n=== {pattern_date} ===\n\n")
                current_date = pattern_date
            
            # Format the compressed entry
            first = info["first_seen"].strftime('%H:%M:%S')
            last = info["last_seen"].strftime('%H:%M:%S') if info["last_seen"] else first
            
            if first == last or info["count"] == 1:
                time_str = f"{first}"
            else:
                time_str = f"{first}-{last}"
                
            compressed.write(f"{time_str} | {info['level']:7} | {info['count']:6} | {pattern}\n")
    
    print(f"Analysis complete. Results in log_patterns_report.txt and compressed_log.txt")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_log.py <log_file>")
        sys.exit(1)
    
    analyze_log(sys.argv[1])