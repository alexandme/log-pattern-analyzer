#\!/bin/bash

LOG_FILE="$1"
OUTPUT_FILE="log_patterns.txt"

# Extract patterns with simple tools
echo "Analyzing log patterns in $LOG_FILE..."
echo "PATTERN_COUNT | LEVEL | MESSAGE_PATTERN" > "$OUTPUT_FILE"
echo "-----------------------------------------" >> "$OUTPUT_FILE"

# Process only lines with timestamp pattern
grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} - " "$LOG_FILE" | 
  # Extract level and message, normalize messages by replacing numbers
  sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} - ([A-Z]+) - (.*)/\1 \2/' |
  sed -E 's/[0-9]+(\.[0-9]+)?/<N>/g' |
  sed -E 's/0x[0-9a-fA-F]+/<ADDR>/g' |
  # Count unique patterns
  sort | uniq -c | sort -nr | head -50 |
  # Format output
  awk '{printf "%12d | %5s | %s\n", $1, $2, substr($0, index($0, $3))}' >> "$OUTPUT_FILE"

# Extract error patterns specifically
echo "" >> "$OUTPUT_FILE"
echo "ERROR PATTERNS:" >> "$OUTPUT_FILE"
echo "-----------------------------------------" >> "$OUTPUT_FILE"
grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} - ERROR" "$LOG_FILE" |
  sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} - ERROR - (.*)/\1/' |
  sed -E 's/[0-9]+(\.[0-9]+)?/<N>/g' |
  sort | uniq -c | sort -nr |
  awk '{printf "%8d | %s\n", $1, substr($0, index($0, $2))}' >> "$OUTPUT_FILE"

# Extract time ranges for errors
echo "" >> "$OUTPUT_FILE"
echo "ERROR TIME RANGES:" >> "$OUTPUT_FILE"
echo "-----------------------------------------" >> "$OUTPUT_FILE"
grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} - ERROR" "$LOG_FILE" |
  awk 'NR==1 {first=$1" "$2} END {last=$1" "$2; print "First error: "first"\nLast error: "last}' >> "$OUTPUT_FILE"

echo "Analysis complete. Results in $OUTPUT_FILE"
