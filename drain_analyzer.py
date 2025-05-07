#!/Users/alyushina/miniforge3/envs/logpai/bin/python
import re
import sys
import os
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
import random
import pandas as pd

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


class DrainAnalyzer:
    """
    Log analyzer inspired by Drain for pattern extraction with samples.
    This implementation supports custom log formats and preprocessing rules.
    """
    def __init__(
        self,
        log_format=None,
        indir="./",
        outdir="./result/",
        rex=None,
        similarity_threshold=0.5,
        max_child=100,
        depth=4
    ):
        """
        Initialize the log analyzer with specified parameters.
        
        Args:
            log_format: Format of the log (e.g., '<Timestamp> <Level> <Content>')
            indir: Input directory containing log files
            outdir: Output directory for results
            rex: List of regular expressions for preprocessing
            similarity_threshold: Threshold for pattern similarity
            max_child: Maximum number of children for Drain tree nodes
            depth: Depth of the Drain parsing tree
        """
        self.log_format = log_format
        self.indir = indir
        self.outdir = outdir
        self.st = similarity_threshold
        self.max_child = max_child
        self.depth = depth
        
        # Default replacements for normalization
        self.default_replacements = [
            (re.compile(r'\d+\.\d+s'), '<TIME>s'),
            (re.compile(r'\b\d+\b'), '<N>'),
            (re.compile(r'0x[0-9a-f]+'), '<ADDR>'),
            (re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), '<UUID>'),
            (re.compile(r'\/[\/\w\.\-]+\/[\w\.\-]+'), '<PATH>'),
            (re.compile(r'\d+,\d+,\d+'), '<N>,<N>,<N>'),
            (re.compile(r'\d+\.\d+'), '<N>.<N>'),
        ]
        
        # Additional regular expressions for preprocessing
        self.rex = rex if rex else []
        
        # For simple log pattern matching with samples
        self.log_patterns = {}  # {template_str: LogPattern}
        
        # For temporal analysis
        self.time_slots = defaultdict(list)  # {time_slot: [(pattern_id, count)]}
        
        # Format detection
        if not self.log_format:
            # Default log format (timestamp - level - content)
            self.log_format = '<Date> <Time> - <Level> - <Content>'
            self.log_line_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([A-Z]+) - (.*)')
        else:
            # Generate regex for the specified log format
            self.headers, self.log_line_pattern = self.generate_logformat_regex(self.log_format)
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)

    def generate_logformat_regex(self, log_format):
        """Generate a regular expression based on the log format string."""
        headers = []
        splitters = re.split(r'(<[^<>]+>)', log_format)
        regex = ''
        for k in range(len(splitters)):
            if k % 2 == 0:
                splitter = re.sub(' +', r'\\s+', splitters[k])
                regex += splitter
            else:
                header = splitters[k].strip('<').strip('>')
                regex += f'(?P<{header}>.*?)'
                headers.append(header)
        regex = re.compile('^' + regex + '$')
        return headers, regex

    def preprocess(self, content):
        """Apply preprocessing rules to normalize the log content."""
        for current_rex in self.rex:
            content = re.sub(current_rex, '<*>', content)
        return content

    def normalize_message(self, message):
        """Normalize log message by replacing variable parts with placeholders."""
        normalized = message
        for pattern, replacement in self.default_replacements:
            normalized = pattern.sub(replacement, normalized)
        return normalized

    def parse_log_file(self, log_file):
        """
        Parse a log file and extract patterns.
        
        Args:
            log_file: Name of the log file to parse
        
        Returns:
            True on success, False on failure
        """
        print(f"Parsing log file: {os.path.join(self.indir, log_file)}")
        self.log_file = log_file
        
        try:
            # Load log data
            df_log = self.log_to_dataframe(os.path.join(self.indir, log_file))
            
            # Process each log line
            for idx, row in df_log.iterrows():
                line_id = row['LineId']
                
                # Apply preprocessing to content
                content = self.preprocess(row['Content'])
                
                # Get level if available
                level = row.get('Level', '')
                
                # Get timestamp
                timestamp = None
                if 'Date' in row and 'Time' in row:
                    timestamp_str = f"{row['Date']} {row['Time']}"
                    try:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        try:
                            # Try alternative format
                            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                        except ValueError:
                            timestamp = datetime.now()  # Fallback
                elif 'Timestamp' in row:
                    try:
                        timestamp = datetime.strptime(row['Timestamp'], '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        timestamp = datetime.now()  # Fallback
                else:
                    timestamp = datetime.now()  # Fallback
                
                # Normalize message
                normalized_msg = self.normalize_message(content)
                
                # Create a pattern key (include level if available)
                pattern_key = f"{level} - {normalized_msg}" if level else normalized_msg
                
                # Check if pattern already exists
                if pattern_key not in self.log_patterns:
                    self.log_patterns[pattern_key] = LogPattern(
                        template=pattern_key,
                        level=level,
                        first_seen=timestamp
                    )
                
                # Add this log to the pattern
                original_line = ' '.join(str(v) for k, v in row.items() if k not in ['LineId'])
                self.log_patterns[pattern_key].add_log(line_id, timestamp, original_line)
                
                # For temporal analysis - group by minute
                time_slot = timestamp.replace(second=0)
                self.time_slots[time_slot].append((pattern_key, line_id))
                
                if idx % 10000 == 0:
                    print(f"Processed {idx} lines, found {len(self.log_patterns)} unique patterns")
            
            print(f"Finished processing {len(df_log)} lines. Found {len(self.log_patterns)} unique log patterns.")
            
            return True
            
        except Exception as e:
            print(f"Error processing log file: {str(e)}")
            return False

    def log_to_dataframe(self, log_file):
        """Convert a log file to a pandas DataFrame based on the log format."""
        log_messages = []
        line_count = 0
        
        if self.log_format:
            # Use the format-based regex
            with open(log_file, 'r', errors='replace') as fin:
                for line in fin.readlines():
                    try:
                        match = self.log_line_pattern.search(line.strip())
                        if match:
                            message = [match.group(header) for header in self.headers]
                            log_messages.append(message)
                            line_count += 1
                    except Exception as e:
                        print(f"[Warning] Skip line: {line}")
            
            # Convert to DataFrame
            logdf = pd.DataFrame(log_messages, columns=self.headers)
            
        else:
            # Fallback for unstructured logs
            with open(log_file, 'r', errors='replace') as fin:
                for line in fin.readlines():
                    log_messages.append({'Content': line.strip()})
                    line_count += 1
            
            # Convert to DataFrame
            logdf = pd.DataFrame(log_messages)
        
        # Add line IDs
        logdf.insert(0, 'LineId', None)
        logdf['LineId'] = [i + 1 for i in range(line_count)]
        
        print(f"Total lines: {len(logdf)}")
        return logdf

    def generate_temporal_summary(self, interval_minutes=1, output_file=None):
        """
        Generate a temporal summary of log patterns with samples.
        
        Args:
            interval_minutes: The interval in minutes for each time slot (default: 1)
            output_file: Output file to write the summary (default: log_file_temporal_summary.txt)
        """
        if not self.log_patterns:
            print("No log patterns found. Please parse a log file first.")
            return
        
        # Set default output file if not specified
        if not output_file:
            output_file = os.path.join(self.outdir, f"{self.log_file.split('.')[0]}_pattern_samples.txt")
        
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

    def generate_pattern_summary(self, output_file=None):
        """
        Generate a summary of all log patterns sorted by frequency.
        
        Args:
            output_file: Output file to write the summary (default: log_file_patterns.txt)
        """
        if not self.log_patterns:
            print("No log patterns found. Please parse a log file first.")
            return
        
        # Set default output file if not specified
        if not output_file:
            output_file = os.path.join(self.outdir, f"{self.log_file.split('.')[0]}_patterns.txt")
        
        # Sort patterns by count
        sorted_patterns = sorted(
            self.log_patterns.items(), 
            key=lambda x: x[1].count, 
            reverse=True
        )
        
        # Write the pattern summary
        with open(output_file, 'w') as out:
            out.write("LOG PATTERN SUMMARY\n")
            out.write("=" * 80 + "\n\n")
            
            out.write(f"Total log lines processed: {sum(p.count for _, p in sorted_patterns)}\n")
            out.write(f"Unique log patterns: {len(sorted_patterns)}\n\n")
            
            # Write pattern statistics by level
            level_counts = defaultdict(int)
            for _, pattern in sorted_patterns:
                level_counts[pattern.level] += 1
            
            out.write("PATTERNS BY LEVEL:\n")
            for level, count in sorted(level_counts.items(), key=lambda x: x[1], reverse=True):
                out.write(f"  {level}: {count} patterns\n")
            
            out.write("\n" + "=" * 80 + "\n\n")
            
            # Write patterns sorted by frequency
            out.write("PATTERNS BY FREQUENCY:\n\n")
            for i, (pattern_key, pattern) in enumerate(sorted_patterns, 1):
                out.write(f"Pattern {i} ({pattern.count} occurrences):\n")
                out.write(f"  Level: {pattern.level}\n")
                out.write(f"  First seen: {pattern.first_seen}\n")
                out.write(f"  Last seen: {pattern.last_seen}\n")
                out.write(f"  Template: {pattern_key}\n")
                
                # Add samples
                samples = pattern.get_random_samples(3)
                if samples:
                    out.write("  Samples:\n")
                    for i, (timestamp, sample) in enumerate(samples, 1):
                        out.write(f"    {i}. {sample}\n")
                
                out.write("\n")
            
            print(f"Pattern summary saved to: {output_file}")

def main():
    """Main function to run the analyzer from command line."""
    if len(sys.argv) < 2:
        print("Usage: python drain_analyzer.py <log_file> [interval_minutes] [log_format]")
        print("Example log formats:")
        print("  '<Date> <Time> - <Level> - <Content>'")
        print("  '<Timestamp> <Level> <Component>: <Content>'")
        sys.exit(1)
    
    # Process command-line arguments
    log_file = sys.argv[1]
    interval_minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    log_format = sys.argv[3] if len(sys.argv) > 3 else '<Date> <Time> - <Level> - <Content>'
    
    # Define regular expressions for preprocessing (optional)
    rex = [
        r'\d+\.\d+\.\d+\.\d+',  # IP addresses
        r'\b\d{2}:\d{2}:\d{2}\b',  # Time
        r'\b\d{4}-\d{2}-\d{2}\b',  # Date
        r'0x[0-9a-fA-F]+',  # Hexadecimal
        r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'  # UUID
    ]
    
    # Initialize the analyzer
    analyzer = DrainAnalyzer(
        log_format=log_format,
        indir=os.path.dirname(log_file) or "./",
        outdir="./results/",
        rex=rex
    )
    
    # Parse the log file
    if analyzer.parse_log_file(os.path.basename(log_file)):
        # Generate summaries
        analyzer.generate_temporal_summary(interval_minutes)
        analyzer.generate_pattern_summary()
        print("Analysis complete!")

if __name__ == "__main__":
    main()