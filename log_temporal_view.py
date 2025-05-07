#!/usr/bin/env python3
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

def create_temporal_summary(log_file, interval_minutes=1):
    """
    Create a temporal summary of log patterns, showing when patterns occurred and their frequency.
    
    Args:
        log_file: Path to the log file
        interval_minutes: Time interval in minutes for grouping (default: 1 minute)
    """
    # Regular expression for log pattern
    log_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([A-Z]+) - (.*)')
    
    # Patterns to normalize messages (replace variable parts with placeholders)
    replacements = [
        (re.compile(r'\d+\.\d+s'), '<TIME>s'),
        (re.compile(r'\b\d+\b'), '<N>'),
        (re.compile(r'0x[0-9a-f]+'), '<ADDR>'),
        (re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), '<UUID>'),
        (re.compile(r'\/[\/\w\.\-]+\/[\w\.\-]+'), '<PATH>'),
    ]
    
    # Data structure: {time_slot: {pattern: count}}
    time_slots = defaultdict(lambda: defaultdict(int))
    
    # Process the log file
    print(f"Processing {log_file}...")
    with open(log_file, 'r', errors='replace') as f:
        for line in f:
            match = log_pattern.search(line)
            if not match:
                continue
                
            timestamp_str, level, message = match.groups()
            
            try:
                # Parse timestamp and create time slot
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                # Round down to nearest interval
                minutes = (timestamp.minute // interval_minutes) * interval_minutes
                time_slot = timestamp.replace(minute=minutes, second=0)
            except ValueError:
                continue
            
            # Normalize the message
            normalized_msg = message
            for pattern, replacement in replacements:
                normalized_msg = pattern.sub(replacement, normalized_msg)
            
            # Combine level and normalized message as the pattern
            pattern = f"{level} - {normalized_msg}"
            
            # Increment count for this pattern in this time slot
            time_slots[time_slot][pattern] += 1
    
    # Output the temporal summary
    with open("log_temporal_summary.txt", "w") as out:
        out.write(f"TEMPORAL LOG PATTERN SUMMARY (interval: {interval_minutes} minute(s))\n")
        out.write("=" * 80 + "\n\n")
        
        for time_slot in sorted(time_slots.keys()):
            slot_end = time_slot + timedelta(minutes=interval_minutes)
            out.write(f"{time_slot.strftime('%H:%M')} - {slot_end.strftime('%H:%M')}\n")
            out.write("-" * 40 + "\n")
            
            # Sort patterns by count (descending)
            sorted_patterns = sorted(time_slots[time_slot].items(), key=lambda x: x[1], reverse=True)
            
            for pattern, count in sorted_patterns:
                # Truncate very long patterns for readability
                if len(pattern) > 150:
                    pattern = pattern[:147] + "..."
                out.write(f"  {count} messages with pattern: {pattern}\n")
            
            out.write("\n")
    
    print(f"Temporal summary created: log_temporal_summary.txt")

if __name__ == "__main__":
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print("Usage: python log_temporal_view.py <log_file> [interval_minutes]")
        sys.exit(1)
    
    log_file = sys.argv[1]
    interval_minutes = int(sys.argv[2]) if len(sys.argv) == 3 else 1
    
    create_temporal_summary(log_file, interval_minutes)