import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="Embed a binary file into a Java class as chunked byte arrays."
    )
    parser.add_argument("input_file", help="Path to the binary file to embed")
    parser.add_argument("output_c_file", help="Path to write the generated Java source")
    parser.add_argument("--var-name", help="Name of var for binary data", default="binary_data")
    return parser.parse_args()


def main():
    args = parse_args()

    with open(args.input_file, 'rb') as f:
        data = f.read()
    
    lines = []
    parts = args.output_c_file.split(".")
    if len(parts) > 1:
        parts = parts[:-1]
    name = ".".join(parts)
    guard_name = f"GUARD_{".".join(parts)}"
    lines.append(f"#ifndef {guard_name}")
    lines.append(f"#define {guard_name}")
    lines.append("#include <stdint.h>")
    lines.append(f"\nuint8_t {args.var_name}[] = {{ {", ".join(str(n) for n in data)} }};\n")
    lines.append("#endif")


    with open(args.output_c_file, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
