#!/bin/bash
# Automated test script for multiple safe targets

echo "=== Testing Penetration Testing Toolkit ==="
echo

# Safe test targets
TARGETS=(
    "localhost"
    "127.0.0.1" 
    "example.com"
    "httpbin.org"
)

for target in "${TARGETS[@]}"; do
    echo "=== Testing target: $target ==="
    
    # Create input file for automated testing
    echo -e "3\n0" > input.txt
    
    # Run full workflow then exit
    ./pentest.exe "$target" < input.txt
    
    echo "Report for $target:"
    if [ -f "reports/report.json" ]; then
        cat reports/report.json | head -10
        echo "..."
    fi
    echo
    echo "---"
    echo
done

# Cleanup
rm -f input.txt

echo "=== Testing complete ==="
