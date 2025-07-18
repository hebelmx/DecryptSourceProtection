import os

PATH= R'E:\Dynamic\Source\DecryptSourceProtection\sW'
KEYWORD = 'SourceProtection'

def scan_directory_for_keyword(directory, keyword, output_file="SourceProtection.txt", context=32):
    matches = []
    file_count = 0

    for root, _, files in os.walk(directory):
        print(f"Entering directory: {root}")  # <--- Add this line
        for filename in files:
            file_count += 1
            if file_count % 100 == 0:
                print(f"Scanned {file_count} files...")

            full_path = os.path.join(root, filename)
            try:
                with open(full_path, 'rb') as f:
                    content = f.read()

                index = content.find(keyword.encode('utf-8'))
                if index != -1:
                    start = max(0, index - context)
                    end = index + len(keyword) + context
                    preview = content[start:end]

                    matches.append({
                        "file": full_path,
                        "offset": index,
                        "context_hex": preview.hex(),
                        "context_str": ''.join([chr(b) if 32 <= b < 127 else '.' for b in preview])
                    })

                    print(f"Match found in: {full_path}")

            except Exception:
                continue  # Ignore unreadable files

    if matches:
        with open(output_file, 'w', encoding='utf-8') as out:
            for match in matches:
                out.write(f"File: {match['file']}\n")
                out.write(f"Offset: {match['offset']}\n")
                out.write(f"Context (hex): {match['context_hex']}\n")
                out.write(f"Context (ascii): {match['context_str']}\n")
                out.write("-" * 80 + "\n")
        print(f"Finished. {len(matches)} matches saved to {output_file}")
    else:
        print("No matches found.")

# Run as a script
if __name__ == "__main__":
    import sys
    scan_directory_for_keyword(sys.argv[1] if len(sys.argv) > 1 else  PATH, "SourceProtection")
