#!/usr/bin/env python3
import re
import sys
import os
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
import random

class LogPattern:
    """Represents a log message pattern with its occurrences."""
    def __init__(self, template=None, level="", first_seen=None):
        self.template = template
        self.level = level
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.log_ids = []  # List of line IDs that match this pattern
        self.log_samples = []  # Original log lines as samples
        self.count = 0

    def add_log(self, log_id, timestamp, original_message):
        self.log_ids.append(log_id)
        if len(self.log_samples) < 10:  # Keep up to 10 samples
            self.log_samples.append((timestamp, original_message))
        elif random.random() < 0.3:  # Randomly replace samples to get a better distribution
            idx = random.randint(0, len(self.log_samples) - 1)
            self.log_samples[idx] = (timestamp, original_message)
        
        self.count += 1
        if timestamp < self.first_seen:
            self.first_seen = timestamp
        if timestamp > self.last_seen:
            self.last_seen = timestamp

    def get_random_samples(self, max_samples=3):
        """Get a random selection of sample logs for this pattern."""
        if not self.log_samples:
            return []
        
        if len(self.log_samples) <= max_samples:
            return self.log_samples
        
        # Get samples from beginning, middle, and end to show the distribution
        if max_samples == 3 and len(self.log_samples) > 3:
            indices = [0, len(self.log_samples) // 2, len(self.log_samples) - 1]
            return [self.log_samples[i] for i in indices]
        
        # Otherwise select random samples
        return random.sample(self.log_samples, max_samples)


class LogParser:
    """Log parser inspired by Drain for pattern extraction with samples."""
    def __init__(self, log_file_path, similarity_threshold=0.5):
        self.log_file_path = log_file_path
        self.similarity_threshold = similarity_threshold
        
        # Dictionary to store log patterns: {template_str: LogPattern}
        self.log_patterns = {}
        
        # Log line pattern with regex groups for timestamp, level, and message
        self.log_line_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([A-Z]+) - (.*)')
        
        # Patterns to replace for normalization
        self.replacements = [
            (re.compile(r'\d+\.\d+s'), '<TIME>s'),
            (re.compile(r'\b\d+\b'), '<N>'),
            (re.compile(r'0x[0-9a-f]+'), '<ADDR>'),
            (re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), '<UUID>'),
            (re.compile(r'\/[\/\w\.\-]+\/[\w\.\-]+'), '<PATH>'),
            (re.compile(r'\d+,\d+,\d+'), '<N>,<N>,<N>'),
            (re.compile(r'\d+\.\d+'), '<N>.<N>'),
        ]
        
        # For temporal analysis
        self.time_slots = defaultdict(list)  # {time_slot: [(pattern_id, count)]}

    def normalize_message(self, message):
        """Normalize log message by replacing variable parts with placeholders."""
        normalized = message
        for pattern, replacement in self.replacements:
            normalized = pattern.sub(replacement, normalized)
        return normalized

    def parse_log_line(self, line, line_id):
        """Parse a log line and extract timestamp, level, and message."""
        match = self.log_line_pattern.search(line)
        if not match:
            return None
        
        timestamp_str, level, message = match.groups()
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return None
        
        normalized_msg = self.normalize_message(message)
        
        # Create a pattern key that combines level and message
        pattern_key = f"{level} - {normalized_msg}"
        
        # Check if pattern already exists
        if pattern_key not in self.log_patterns:
            self.log_patterns[pattern_key] = LogPattern(
                template=pattern_key,
                level=level,
                first_seen=timestamp
            )
        
        # Add this log to the pattern
        self.log_patterns[pattern_key].add_log(line_id, timestamp, line.strip())
        
        # For temporal analysis - group by minute
        time_slot = timestamp.replace(second=0)
        self.time_slots[time_slot].append((pattern_key, line_id))
        
        return {
            'line_id': line_id,
            'timestamp': timestamp,
            'level': level,
            'message': message,
            'normalized': normalized_msg,
            'pattern_key': pattern_key
        }

    def parse(self):
        """Parse the log file and extract patterns."""
        print(f"Parsing log file: {self.log_file_path}")
        line_id = 0
        try:
            with open(self.log_file_path, 'r', errors='replace') as f:
                for line in f:
                    line_id += 1
                    self.parse_log_line(line, line_id)
                    
                    if line_id % 10000 == 0:
                        print(f"Processed {line_id} lines, found {len(self.log_patterns)} unique patterns")
            
            print(f"Finished processing {line_id} lines. Found {len(self.log_patterns)} unique log patterns.")
            
        except Exception as e:
            print(f"Error processing log file: {str(e)}")
            return False
        
        return True

    def generate_temporal_summary(self, interval_minutes=1, output_file='log_pattern_samples.txt'):
        """
        Generate a temporal summary of log patterns with samples.
        
        Args:
            interval_minutes: The interval in minutes for each time slot (default: 1)
            output_file: Output file to write the summary (default: log_pattern_samples.txt)
        """
        if not self.log_patterns:
            print("No log patterns found. Please parse the log file first.")
            return
        
        # Combine time slots into larger intervals if needed
        combined_slots = defaultdict(list)
        for time_slot, pattern_ids in self.time_slots.items():
            # Round to the nearest interval
            rounded_slot = time_slot.replace(
                minute=(time_slot.minute // interval_minutes) * interval_minutes
            )
            combined_slots[rounded_slot].extend(pattern_ids)
        
        # Count patterns per time slot
        pattern_counts_by_slot = {}
        for time_slot, pattern_ids in combined_slots.items():
            pattern_counts = defaultdict(int)
            for pattern_key, _ in pattern_ids:
                pattern_counts[pattern_key] += 1
            pattern_counts_by_slot[time_slot] = pattern_counts
        
        # Write the temporal summary
        with open(output_file, 'w') as out:
            out.write(f"TEMPORAL LOG PATTERN SUMMARY WITH SAMPLES (interval: {interval_minutes} minute(s))\n")
            out.write("=" * 100 + "\n\n")
            
            # Process each time slot
            for time_slot in sorted(pattern_counts_by_slot.keys()):
                pattern_counts = pattern_counts_by_slot[time_slot]
                
                # Calculate the end time
                slot_end = time_slot + timedelta(minutes=interval_minutes)
                
                # Write the time slot header
                out.write(f"{time_slot.strftime('%H:%M')} - {slot_end.strftime('%H:%M')}\n")
                out.write("-" * 80 + "\n")
                
                # Write patterns sorted by count (most frequent first)
                for pattern_key, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
                    pattern = self.log_patterns[pattern_key]
                    
                    # Skip patterns with very few occurrences in this time slot
                    if count < 3 and pattern.count > 100:
                        continue
                    
                    # Get samples for this pattern
                    samples = pattern.get_random_samples(3)
                    
                    # Skip if we have no samples
                    if not samples:
                        continue
                    
                    # Print the pattern with its count
                    out.write(f"  {count} messages with pattern: {pattern_key}\n")
                    
                    # Print samples
                    out.write("    SAMPLES:\n")
                    for i, (_, sample) in enumerate(samples, 1):
                        out.write(f"    {i}. {sample}\n")
                    
                    out.write("\n")
                
                out.write("\n")
            
            print(f"Temporal summary with samples saved to: {output_file}")

def main():
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print("Usage: python log_pattern_drain.py <log_file> [interval_minutes]")
        sys.exit(1)
    
    log_file = sys.argv[1]
    interval_minutes = int(sys.argv[2]) if len(sys.argv) == 3 else 1
    
    parser = LogParser(log_file)
    if parser.parse():
        parser.generate_temporal_summary(interval_minutes)

if __name__ == "__main__":
    main()