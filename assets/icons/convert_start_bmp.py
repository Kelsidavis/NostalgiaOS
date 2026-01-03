#!/usr/bin/env python3
"""
Convert start16.bmp to Rust source code.
"""
import struct
from pathlib import Path

def read_bmp_4bit(bmp_path):
    """Read 4-bit BMP and convert to RGBA."""
    with open(bmp_path, 'rb') as f:
        # Read BMP header
        header = f.read(14)
        if header[0:2] != b'BM':
            raise ValueError("Not a BMP file")

        pixel_offset = struct.unpack('<I', header[10:14])[0]

        # Read DIB header
        dib_size = struct.unpack('<I', f.read(4))[0]
        width = struct.unpack('<i', f.read(4))[0]
        height = struct.unpack('<i', f.read(4))[0]
        f.read(2)  # planes
        bit_count = struct.unpack('<H', f.read(2))[0]

        if bit_count != 4:
            raise ValueError(f"Expected 4-bit BMP, got {bit_count}-bit")

        # Skip rest of header
        f.seek(14 + dib_size)

        # Read palette (16 colors for 4-bit)
        palette = []
        for i in range(16):
            b, g, r, reserved = struct.unpack('BBBB', f.read(4))
            # Treat magenta (pink) as transparent
            if r > 200 and b > 200 and g < 50:
                palette.append((r, g, b, 0))  # Transparent
            else:
                palette.append((r, g, b, 255))  # RGBA

        # Read pixel data
        f.seek(pixel_offset)

        # Calculate row size (must be multiple of 4)
        row_size = ((width * 4 + 31) // 32) * 4

        # Read pixels (bottom-to-top)
        pixels = []
        for y in range(height - 1, -1, -1):
            row_data = f.read(row_size)
            for x in range(width):
                byte_index = x // 2
                if x % 2 == 0:
                    # High nibble
                    palette_index = (row_data[byte_index] >> 4) & 0x0F
                else:
                    # Low nibble
                    palette_index = row_data[byte_index] & 0x0F

                r, g, b, a = palette[palette_index]
                pixels.extend([r, g, b, a])

        return width, height, pixels

def generate_rust_code(width, height, pixels):
    """Generate Rust source code for the Windows logo."""
    code = f"""// Auto-generated from start16.bmp
pub const WINDOWS_LOGO_WIDTH: usize = {width};
pub const WINDOWS_LOGO_HEIGHT: usize = {height};
pub const WINDOWS_LOGO_DATA: [u8; {len(pixels)}] = [
"""

    # Format as bytes, 16 per line
    for i in range(0, len(pixels), 16):
        chunk = pixels[i:i+16]
        code += "    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n"

    code += "];\n"
    return code

def main():
    icons_dir = Path(__file__).parent
    bmp_path = icons_dir / "start16.bmp"
    output_file = icons_dir.parent.parent / "kernel" / "src" / "win32k" / "user" / "windows_logo.rs"

    print(f"Converting {bmp_path}...")
    width, height, pixels = read_bmp_4bit(bmp_path)

    rust_code = generate_rust_code(width, height, pixels)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        f.write(rust_code)

    print(f"Generated {output_file}")
    print(f"Size: {width}x{height}, {len(pixels)} bytes")

if __name__ == "__main__":
    main()
