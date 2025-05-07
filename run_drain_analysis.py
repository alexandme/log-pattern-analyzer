#!/Users/alyushina/miniforge3/envs/logpai/bin/python
from drain_analyzer import DrainAnalyzer
import os
import sys

def main():
    """Demo script for running the Drain-inspired log analyzer."""
    # Set default log file path
    if len(sys.argv) < 2:
        log_file = "2025-05-06_log.txt"
        print(f"No log file specified, using default: {log_file}")
    else:
        log_file = sys.argv[1]
    
    # Get the current directory and create a results directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(current_dir, log_file)
    results_dir = os.path.join(current_dir, "drain_results")
    
    # Check if the log file exists
    if not os.path.exists(log_path):
        print(f"Error: Log file {log_path} not found.")
        sys.exit(1)
    
    # Create the results directory if it doesn't exist
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    
    # Define regular expressions for preprocessing
    rex = [
        r'\d+\.\d+\.\d+\.\d+',       # IP addresses
        r'0x[0-9a-fA-F]+',           # Hex addresses
        r'/[\w/.-]+',                # File paths
    ]
    
    # Initialize the analyzer
    analyzer = DrainAnalyzer(
        log_format='<Date> <Time> - <Level> - <Content>',  # Format for your log
        indir=current_dir,
        outdir=results_dir,
        rex=rex,
        similarity_threshold=0.5,
        depth=4
    )
    
    # Parse the log file
    if analyzer.parse_log_file(log_file):
        # Generate temporal summary with 1-minute intervals
        analyzer.generate_temporal_summary(interval_minutes=1)
        
        # Generate overall pattern summary
        analyzer.generate_pattern_summary()
        
        print(f"Analysis complete! Results saved to {results_dir}")

if __name__ == "__main__":
    main()