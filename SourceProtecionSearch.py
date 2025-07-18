import os
import re

PATH= R'E:\Dynamic\Source\DecryptSourceProtection\sW'
KEYWORD = 'SourceProtection'


def scan_directory_for_keyword(directory, keyword, output_file="SourceProtection.txt", context=32):
    matches = []

    for root, _, files in os.walk(directory):
        for filename in files:
            full_path = os.path.join(root, filename)

            try:
                with open(full_path, 'rb') as f:
                    content = f.read()

                # Search in binary content
                if keyword.encode('utf-8') in content:
                    offset = content.find(keyword.encode('utf-8'))
                    start = max(0, offset - context)
                    end = offset + len(keyword) + context
                    preview = content[start:end]

                    matches.append({
                        "file": full_path,
                        "offset": offset,
                        "context_hex": preview.hex(),
                        "context_str": ''.join([chr(b) if 32 <= b < 127 else '.' for b in preview])
                    })
            except Exception as e:
                continue  # Skip files we can't read

    # Write to output file
    with open(output_file, 'w', encoding='utf-8') as out:
        for match in matches:
            out.write(f"File: {match['file']}\n")
            out.write(f"Offset: {match['offset']}\n")
            out.write(f"Context (hex): {match['context_hex']}\n")
            out.write(f"Context (ascii): {match['context_str']}\n")
            out.write("-" * 80 + "\n")

    print(f"Scan complete. {len(matches)} matches saved to {output_file}")

# Usage example
if __name__ == "__main__":
    import sys
    scan_directory_for_keyword(sys.argv[1] if len(sys.argv) > 1 else PATH, "SourceProtection")
