import argparse

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


def positive_int(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def parse_args():
    parser = argparse.ArgumentParser(
        description="Embed a binary file into a Java class as chunked byte arrays."
    )
    parser.add_argument("input_file", help="Path to the binary file to embed")
    parser.add_argument("output_java_file", help="Path to write the generated Java source")
    parser.add_argument(
        "-c",
        "--chunk-size",
        type=positive_int,
        default=8000,
        help="Maximum number of bytes per generated chunk method (default: %(default)s)",
    )
    parser.add_argument(
        "-n",
        "--class-name",
        default="ByteData",
        help="Name of the generated Java class (default: %(default)s)",
    )
    parser.add_argument(
        "-p",
        "--package-name",
        help="Optional Java package name for the generated class",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    java_code = generate_java_class(
        args.input_file,
        args.class_name,
        args.chunk_size,
        args.package_name,
    )

    with open(args.output_java_file, "w") as f:
        f.write(java_code)

    print(
        f"Generated Java class '{args.class_name}' with chunk size "
        f"{args.chunk_size} -> {args.output_java_file}"
    )


if __name__ == "__main__":
    main()
