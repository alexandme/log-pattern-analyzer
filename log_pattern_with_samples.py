#!/usr/bin/env python3
import re
import sys
import os
from collections import defaultdict
from datetime import datetime
import random

def create_pattern_with_samples(log_file, min_occurrences=5, samples_per_pattern=3, interval_minutes=5):
    """
    Create a temporal summary of log patterns with actual sample lines
    for patterns that repeat more than min_occurrences times.
    
    Args:
        log_file: Path to the log file
        min_occurrences: Minimum number of occurrences to include pattern samples
        samples_per_pattern: Number of sample lines to include per pattern
        interval_minutes: Time interval in minutes for grouping
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
    
    # Data structure: {time_slot: {pattern: {'count': N, 'samples': [lines]}}}
    time_slots = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'samples': []}))
    
    # Original lines matching each pattern
    pattern_samples = defaultdict(list)
    
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
            
            # Store the original line
            original_line = line.strip()
            
            # Normalize the message
            normalized_msg = message
            for pattern, replacement in replacements:
                normalized_msg = pattern.sub(replacement, normalized_msg)
            
            # Combine level and normalized message as the pattern
            pattern = f"{level} - {normalized_msg}"
            
            # Increment count for this pattern in this time slot
            time_slots[time_slot][pattern]['count'] += 1
            
            # Store sample if we haven't collected enough yet
            if len(time_slots[time_slot][pattern]['samples']) < samples_per_pattern:
                time_slots[time_slot][pattern]['samples'].append(original_line)
            # Randomly replace an existing sample with probability 1/N to ensure representative sampling
            elif random.random() < 1/time_slots[time_slot][pattern]['count']:
                replace_idx = random.randint(0, samples_per_pattern - 1)
                time_slots[time_slot][pattern]['samples'][replace_idx] = original_line
    
    # Output the temporal summary with samples
    with open("log_pattern_samples.txt", "w") as out:
        out.write(f"TEMPORAL LOG PATTERN SUMMARY WITH SAMPLES (interval: {interval_minutes} minute(s))\n")
        out.write("=" * 100 + "\n\n")
        
        for time_slot in sorted(time_slots.keys()):
            slot_end = time_slot.replace(minute=time_slot.minute + interval_minutes)
            out.write(f"{time_slot.strftime('%H:%M')} - {slot_end.strftime('%H:%M')}\n")
            out.write("-" * 80 + "\n")
            
            # Sort patterns by count (descending)
            sorted_patterns = sorted(time_slots[time_slot].items(), key=lambda x: x[1]['count'], reverse=True)
            
            for pattern, data in sorted_patterns:
                count = data['count']
                samples = data['samples']
                
                # Only include patterns that meet minimum occurrence threshold
                if count >= min_occurrences:
                    # Truncate very long patterns for readability
                    if len(pattern) > 100:
                        pattern = pattern[:97] + "..."
                    
                    out.write(f"  {count} messages with pattern: {pattern}\n")
                    
                    if samples:
                        out.write("    SAMPLES:\n")
                        for i, sample in enumerate(samples, 1):
                            out.write(f"    {i}. {sample}\n")
                        out.write("\n")
            out.write("\n")
    
    print(f"Pattern summary with samples created: log_pattern_samples.txt")

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 5:
        print("Usage: python log_pattern_with_samples.py <log_file> [min_occurrences] [samples_per_pattern] [interval_minutes]")
        sys.exit(1)
    
    log_file = sys.argv[1]
    min_occurrences = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    samples_per_pattern = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    interval_minutes = int(sys.argv[4]) if len(sys.argv) > 4 else 5
    
    create_pattern_with_samples(log_file, min_occurrences, samples_per_pattern, interval_minutes)