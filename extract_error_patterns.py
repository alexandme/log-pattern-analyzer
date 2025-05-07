#!/usr/bin/env python3
import re
import sys
from collections import defaultdict

def extract_error_patterns(log_file):
    """Extract error patterns with samples from log file."""
    # Regular expression for log pattern
    log_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (ERROR) - (.*)')
    
    # Store patterns and samples
    error_patterns = defaultdict(list)
    
    # Process the log file
    print(f"Processing {log_file} for error patterns...")
    with open(log_file, 'r', errors='replace') as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                timestamp_str, level, message = match.groups()
                # Normalize by replacing specific values with placeholders
                normalized = re.sub(r'\d+\.\d+s', '<TIME>s', message)
                normalized = re.sub(r'\b\d+\b', '<N>', normalized)
                
                # Truncate very long patterns to a reasonable length for key
                key = normalized[:100]
                
                # Store the original line with timestamp
                error_patterns[key].append((timestamp_str, line.strip()))
    
    # Write results
    with open("error_patterns_with_samples.txt", "w") as out:
        out.write("ERROR PATTERNS WITH SAMPLES\n")
        out.write("==========================\n\n")
        
        # Sort patterns by count
        sorted_patterns = sorted(error_patterns.items(), key=lambda x: len(x[1]), reverse=True)
        
        for pattern, occurrences in sorted_patterns:
            count = len(occurrences)
            out.write(f"PATTERN ({count} occurrences): {pattern}...\n")
            
            # Get timestamp of first and last occurrence
            first_time = occurrences[0][0]
            last_time = occurrences[-1][0]
            out.write(f"Time range: {first_time} to {last_time}\n\n")
            
            # Write max 5 samples
            out.write("SAMPLES:\n")
            # Take samples from beginning, middle and end
            if count <= 5:
                samples = occurrences
            else:
                # Get samples distributed throughout the timerange
                indices = [0, count//4, count//2, 3*count//4, count-1]
                samples = [occurrences[i] for i in indices]
            
            for i, (_, sample) in enumerate(samples, 1):
                out.write(f"{i}. {sample}\n")
            
            out.write("\n" + "-"*80 + "\n\n")
    
    print(f"Error patterns extracted to error_patterns_with_samples.txt")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_error_patterns.py <log_file>")
        sys.exit(1)
    
    extract_error_patterns(sys.argv[1])