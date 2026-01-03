#!/usr/bin/env python3
"""
Convert Windows .ico files to Rust source code with embedded pixel data.
Extracts 32x32 RGBA bitmaps from .ico files.
"""

import struct
import sys
from pathlib import Path

def parse_ico(ico_path):
    """Parse ICO file and extract 32x32 image data."""
    with open(ico_path, 'rb') as f:
        # Read ICONDIR header
        reserved = struct.unpack('<H', f.read(2))[0]
        type_field = struct.unpack('<H', f.read(2))[0]
        count = struct.unpack('<H', f.read(2))[0]

        if reserved != 0 or type_field != 1:
            raise ValueError(f"Not a valid ICO file: {ico_path}")

        # Find 32x32 image
        best_entry = None
        for i in range(count):
            width = struct.unpack('<B', f.read(1))[0]
            height = struct.unpack('<B', f.read(1))[0]
            color_count = struct.unpack('<B', f.read(1))[0]
            reserved = struct.unpack('<B', f.read(1))[0]
            planes = struct.unpack('<H', f.read(2))[0]
            bit_count = struct.unpack('<H', f.read(2))[0]
            bytes_in_res = struct.unpack('<I', f.read(4))[0]
            image_offset = struct.unpack('<I', f.read(4))[0]

            # width/height of 0 means 256x256
            if width == 0:
                width = 256
            if height == 0:
                height = 256

            # Prefer 32x32 with highest bit depth
            if width == 32 and height == 32:
                if best_entry is None or bit_count > best_entry[1]:
                    best_entry = (image_offset, bit_count, bytes_in_res)

        if best_entry is None:
            raise ValueError(f"No 32x32 image found in {ico_path}")

        # Read image data
        offset, bit_count, size = best_entry
        f.seek(offset)
        image_data = f.read(size)

        return image_data, bit_count

def bmp_to_rgba(bmp_data, bit_count):
    """Convert BMP data to RGBA pixel array."""
    # Parse DIB header
    header_size = struct.unpack('<I', bmp_data[0:4])[0]
    width = struct.unpack('<i', bmp_data[4:8])[0]
    height = struct.unpack('<i', bmp_data[8:12])[0]

    # Height in ICO is double (includes AND mask)
    actual_height = abs(height) // 2

    if width != 32 or actual_height != 32:
        raise ValueError(f"Expected 32x32, got {width}x{actual_height}")

    # For 32-bit images
    if bit_count == 32:
        # Skip header to get to pixel data
        pixel_offset = 40  # BITMAPINFOHEADER size
        pixels = []

        # BMP is stored bottom-to-top, we want top-to-bottom
        for y in range(31, -1, -1):
            for x in range(32):
                offset = pixel_offset + (y * 32 + x) * 4
                b = bmp_data[offset]
                g = bmp_data[offset + 1]
                r = bmp_data[offset + 2]
                a = bmp_data[offset + 3]
                pixels.extend([r, g, b, a])

        return pixels
    else:
        # For lower bit depths, create a simple placeholder
        # (In production, you'd want to implement proper palette conversion)
        print(f"Warning: {bit_count}-bit icons not fully supported, using placeholder")
        pixels = []
        for i in range(32 * 32):
            pixels.extend([128, 128, 192, 255])  # Gray-blue placeholder
        return pixels

def generate_rust_code(icon_name, pixels):
    """Generate Rust source code for icon data."""
    code = f"""// Auto-generated from {icon_name}.ico
pub const {icon_name.upper()}_WIDTH: usize = 32;
pub const {icon_name.upper()}_HEIGHT: usize = 32;
pub const {icon_name.upper()}_DATA: [u8; {len(pixels)}] = [
"""

    # Format as bytes, 16 per line
    for i in range(0, len(pixels), 16):
        chunk = pixels[i:i+16]
        code += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"

    code += "];\n"
    return code

def main():
    icons_dir = Path(__file__).parent
    output_file = icons_dir.parent.parent / "kernel" / "src" / "win32k" / "user" / "desktop_icons.rs"

    icons = {
        "MY_COMPUTER": "my_computer.ico",
        "MY_DOCUMENTS": "my_documents.ico",
        "RECYCLE_BIN": "recycle_bin.ico",
        "NETWORK_PLACES": "network_places.ico",
    }

    rust_code = "// Auto-generated desktop icon data from Windows XP .ico files\n\n"

    for icon_name, icon_file in icons.items():
        ico_path = icons_dir / icon_file
        print(f"Converting {icon_file}...")

        try:
            image_data, bit_count = parse_ico(ico_path)
            pixels = bmp_to_rgba(image_data, bit_count)
            rust_code += generate_rust_code(icon_name, pixels)
            rust_code += "\n"
        except Exception as e:
            print(f"Error processing {icon_file}: {e}")
            continue

    # Write to Rust source file
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        f.write(rust_code)

    print(f"Generated {output_file}")

if __name__ == "__main__":
    main()
