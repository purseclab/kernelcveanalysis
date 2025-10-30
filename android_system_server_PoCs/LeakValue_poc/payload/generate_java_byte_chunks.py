#!/usr/bin/env python3
import sys
import os
import textwrap

def generate_java_class(input_path, class_name="ByteData", chunk_size=8000, package_name=None):
    with open(input_path, "rb") as f:
        data = f.read()

    num_chunks = (len(data) + chunk_size - 1) // chunk_size

    # Begin Java class
    lines = []
    if package_name:
        lines.append(f"package {package_name};\n")
    lines.append("import java.io.*;")
    lines.append("import java.util.*;")
    lines.append(f"public class {class_name} {{")

    # Generate chunk methods
    for i in range(num_chunks):
        chunk = data[i * chunk_size:(i + 1) * chunk_size]
        byte_literals = ", ".join(f"(byte)0x{b:02X}" for b in chunk)
        lines.append(f"    public static byte[] chunk{i}() {{")
        lines.append(f"        return new byte[]{{ {byte_literals} }};")
        lines.append("    }")
        lines.append("")

    # Generate combined method
    lines.append("    public static byte[] getAllBytes() {")
    lines.append(f"        List<byte[]> chunks = new ArrayList<>({num_chunks});")
    for i in range(num_chunks):
        lines.append(f"        chunks.add(chunk{i}());")
    lines.append("        int totalLen = 0;")
    lines.append("        for (byte[] c : chunks) totalLen += c.length;")
    lines.append("        byte[] all = new byte[totalLen];")
    lines.append("        int pos = 0;")
    lines.append("        for (byte[] c : chunks) {")
    lines.append("            System.arraycopy(c, 0, all, pos, c.length);")
    lines.append("            pos += c.length;")
    lines.append("        }")
    lines.append("        return all;")
    lines.append("    }")

    # End class
    lines.append("}")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print("Usage: python generate_java_byte_chunks.py <input_file> <output_java_file> [chunk_size] [class_name] [package_name]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    chunk_size = int(sys.argv[3]) if len(sys.argv) > 3 else 8000
    class_name = sys.argv[4] if len(sys.argv) > 4 else "ByteData"
    package_name = sys.argv[5] if len(sys.argv) > 5 else None

    java_code = generate_java_class(input_path, class_name, chunk_size, package_name)

    with open(output_path, "w") as f:
        f.write(java_code)

    print(f"Generated Java class '{class_name}' with chunk size {chunk_size} → {output_path}")


if __name__ == "__main__":
    main()
