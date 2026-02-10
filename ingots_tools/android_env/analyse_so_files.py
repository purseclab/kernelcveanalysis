import subprocess
import re
import os

def run_adb_command(command):
    """Executes an ADB command and returns its output."""
    try:
        result = subprocess.run(
            f"adb shell \"{command}\"",
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing ADB command: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Error: 'adb' command not found. Is Android Debug Bridge installed and in your PATH?")
        return None

def get_process_info(pid):
    """Fetches process name and UID for a given PID."""
    status_content = run_adb_command(f"cat /proc/{pid}/status")
    if not status_content:
        return None, None

    process_name = None
    uid = None

    for line in status_content.splitlines():
        if line.startswith("Name:"):
            process_name = line.split(":", 1)[1].strip()
        elif line.startswith("Uid:"):
            # The UID is the first number in the line
            uid = line.split(None, 2)[1].strip()

    return process_name, uid

def get_mapped_so_files(pid):
    """Parses /proc/<pid>/maps to find all mapped .so files."""
    maps_content = run_adb_command(f"cat /proc/{pid}/maps")
    if not maps_content:
        return []

    so_files = set()
    # Regex to find paths ending with .so, potentially followed by other characters
    so_pattern = re.compile(r'.*(\S+\.so)\b.*')

    for line in maps_content.splitlines():
        match = so_pattern.search(line)
        if match:
            # We only care about the file path itself, which is the last part of the line
            path_parts = line.split()
            if path_parts and path_parts[-1].endswith(".so"):
                 # Clean up the path if it's marked as (deleted)
                so_file_path = path_parts[-1].replace('(deleted)', '').strip()
                if os.path.basename(so_file_path) not in [os.path.basename(f) for f in so_files]:
                     so_files.add(so_file_path)


    return sorted(list(so_files))

def main():
    """Main function to orchestrate the process analysis."""
    print("Starting analysis of Android processes...")

    # List all directories in /proc that are purely numeric (representing PIDs)
    pids_output = run_adb_command("ls -d /proc/[0-9]*")
    if not pids_output:
        print("Could not retrieve process list. Is a device connected and authorized?")
        return

    pids = [os.path.basename(p) for p in pids_output.split()]

    print(f"Found {len(pids)} running processes. Analyzing each...")

    for pid in pids:
        # We need to get the process info first to see if we should proceed
        process_name, uid = get_process_info(pid)

        # Some processes might be short-lived or inaccessible, so we check for None
        if not process_name or not uid:
            continue

        so_files = get_mapped_so_files(pid)

        if so_files:
            print("\n----------------------------------------")
            print(f"Process: {process_name}")
            print(f"PID: {pid}")
            print(f"UID: {uid}")
            print("Mapped .so files:")
            for so_file in so_files:
                print(f"  - {so_file}")

    print("\n----------------------------------------")
    print("Analysis complete.")

if __name__ == "__main__":
    main()
