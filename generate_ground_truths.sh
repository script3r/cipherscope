#!/bin/bash

# Ground truth generation script for AST-based CipherScope
# This script generates new ground truth JSONL files for all fixture directories

set -e

echo "Building cipherscope..."
source /usr/local/cargo/env
cargo build --release

echo "Generating ground truths..."

# Function to generate ground truth for a directory
generate_ground_truth() {
    local dir="$1"
    local output_file="$dir/ground_truth.jsonl"
    
    echo "Processing: $dir"
    
    # Run cipherscope on this directory with relative path
    local relative_dir=$(realpath --relative-to=. "$dir")
    if ./target/release/cipherscope --deterministic --output "$output_file" "$relative_dir" 2>/dev/null; then
        if [[ -f "$output_file" && -s "$output_file" ]]; then
            local line_count=$(wc -l < "$output_file")
            echo "  Generated $line_count findings"
        else
            # Remove empty files
            [[ -f "$output_file" ]] && rm "$output_file"
            echo "  No findings"
        fi
    else
        echo "  Warning: Failed to scan $dir"
    fi
}

# Find all directories with source files and generate ground truths
find fixtures -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.hpp" -o -name "*.rs" -o -name "*.py" -o -name "*.java" -o -name "*.go" -o -name "*.js" -o -name "*.php" -o -name "*.m" -o -name "*.mm" -o -name "*.swift" -o -name "*.kt" -o -name "*.erl" \) -exec dirname {} \; | sort -u | while read -r dir; do
    generate_ground_truth "$dir"
done

echo "Ground truth generation complete!"
echo ""
echo "Summary of generated ground truth files:"
find fixtures -name "ground_truth.jsonl" -exec wc -l {} \; | sort -k2