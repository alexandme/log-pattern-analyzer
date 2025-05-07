#\!/bin/bash

LOG_FILE="$1"
OUTPUT_FILE="error_time_analysis.txt"

echo "Analyzing error time distribution..." 

# Extract timestamp and categorize by hour and minute
grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} - ERROR" "$LOG_FILE" | 
  awk '{print $1, $2}' | 
  sort | 
  awk '{
    split($2, t, ":");
    hour_min = t[1] ":" t[2];
    counts[hour_min]++;
  } 
  END {
    print "TIME_SLOT | ERROR_COUNT";
    print "-----------------------";
    for (slot in counts) {
      printf "%-8s | %d\n", slot, counts[slot];
    }
  }' | sort > "$OUTPUT_FILE"

# Create a summary of error messages by type and time range
echo -e "\nERROR TYPES WITH TIME RANGES:" >> "$OUTPUT_FILE"
echo "------------------------------" >> "$OUTPUT_FILE"

grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} - ERROR" "$LOG_FILE" | 
  awk '{
    # Extract timestamp
    timestamp = $1 " " $2;
    
    # Extract error message (remove the timestamp and ERROR prefix)
    msg = substr($0, index($0, "ERROR") + 7);
    
    # Normalize the message
    gsub(/[0-9]+(\.[0-9]+)?/, "<N>", msg);
    
    # Record time ranges and count occurrences
    if (\!(msg in first_seen)) {
      first_seen[msg] = timestamp;
      last_seen[msg] = timestamp;
      count[msg] = 1;
    } else {
      last_seen[msg] = timestamp;
      count[msg]++;
    }
  }
  END {
    # Print sorted by count
    for (msg in count) {
      msgs[count[msg], msg] = msg;
      counts[count[msg], msg] = count[msg];
    }
    
    # Sort by count (descending)
    n = asorti(counts, sorted, "@val_num_desc");
    
    # Print top error patterns with time ranges
    for (i = 1; i <= n; i++) {
      msg = msgs[sorted[i]];
      printf "COUNT: %d | FIRST: %s | LAST: %s | %s\n", 
             count[msg], first_seen[msg], last_seen[msg], msg;
    }
  }' >> "$OUTPUT_FILE"

echo "Analysis complete. Results in $OUTPUT_FILE"
