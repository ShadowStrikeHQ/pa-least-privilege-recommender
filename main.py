import argparse
import logging
import os
import psutil
import subprocess
import sys
import time
from typing import List, Set

try:
    import acl
    from pathspec import PathSpec
    from pathspec.patterns import GitWildMatchPattern
    from rich.console import Console
    from rich.table import Column, Table
except ImportError as e:
    print(f"Error importing dependencies: {e}. Please install them.  (pip install psutil pathspec rich python-acl)")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

console = Console()

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes existing permissions and suggests the least privileged set of permissions required for a user or group to perform a specific task based on recorded activity."
    )
    parser.add_argument(
        "--user", type=str, help="The username to analyze.", required=True
    )
    parser.add_argument(
        "--group", type=str, help="The groupname to analyze.", required=False
    )
    parser.add_argument(
        "--pid", type=int, help="The process ID to monitor.", required=True
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="The duration (in seconds) to monitor the process activity.",
    )
    parser.add_argument(
        "--output", type=str, help="The file to write recommended permissions to.", required=False
    )
    parser.add_argument(
        "--baseline", type=str, help="Path to a file containing a baseline ACL to compare against.", required=False
    )
    return parser.parse_args()


def get_process_executable_path(pid: int) -> str:
    """
    Retrieves the executable path of a process given its PID.

    Args:
        pid: The process ID.

    Returns:
        The executable path of the process, or None if it cannot be determined.
    """
    try:
        process = psutil.Process(pid)
        executable_path = process.exe()
        return executable_path
    except psutil.NoSuchProcess:
        logging.error(f"Process with PID {pid} not found.")
        return None
    except psutil.AccessDenied:
        logging.error(f"Access denied when trying to get information about process {pid}.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def monitor_file_access(pid: int, duration: int) -> Set[str]:
    """
    Monitors file access by a process for a specified duration using `lsof`.

    Args:
        pid: The process ID to monitor.
        duration: The duration (in seconds) to monitor the process.

    Returns:
        A set of file paths accessed by the process.
    """
    accessed_files: Set[str] = set()
    try:
        start_time = time.time()
        while time.time() - start_time < duration:
            # Use lsof to get the files opened by the process
            command = ["lsof", "-p", str(pid), "-Fn"]  # -Fn gets only file paths, -p specifies the PID
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if stderr:
                logging.warning(f"lsof encountered an error: {stderr}")

            for line in stdout.splitlines():
                if line.startswith("n"):
                    file_path = line[1:]  # Remove the 'n' prefix
                    if os.path.exists(file_path): #validate the path exists, security best practice
                         accessed_files.add(file_path)
                    else:
                        logging.warning(f"File {file_path} accessed by process {pid} does not exist.")

            time.sleep(1)  # Check every second
    except FileNotFoundError:
        logging.error("lsof command not found.  Please ensure lsof is installed.")
    except subprocess.CalledProcessError as e:
        logging.error(f"lsof command failed: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during file access monitoring: {e}")

    return accessed_files



def get_current_acl(file_path: str, user: str, group: str = None) -> List[str]:
    """
    Retrieves the current ACL entries for a file.

    Args:
        file_path: The path to the file.
        user: The username to check permissions for.
        group: The groupname to check permissions for (optional).

    Returns:
        A list of ACL entry strings.
    """
    try:
        acl_obj = acl.acl(file_path)
        acl_entries = []
        for entry in acl_obj:
            if entry.tag.name == user or (group and entry.tag.name == group):
                acl_entries.append(str(entry))  # Convert ACL entry to string
        return acl_entries
    except OSError as e:
        logging.error(f"Error getting ACL for {file_path}: {e}")
        return []

def recommend_least_privilege(
    accessed_files: Set[str], user: str, group: str = None
) -> dict:
    """
    Recommends the least privilege permissions for the given user/group based on
    accessed files.

    Args:
        accessed_files: A set of file paths that the user/group needs access to.
        user: The username to check permissions for.
        group: The groupname to check permissions for (optional).

    Returns:
        A dictionary where keys are file paths and values are the recommended
        permissions (e.g., "r--").
    """
    recommendations = {}
    for file_path in accessed_files:
        try:
            if not os.path.exists(file_path):
                logging.warning(f"File {file_path} does not exist. Skipping ACL analysis.")
                continue
            
            # Basic checks: Does the file exist? Is it accessible?
            if not os.access(file_path, os.R_OK):
                logging.warning(f"User doesn't have read access to {file_path}.  This might impact the accuracy of least privilege recommendation.")

            required_permissions = ""

            if os.access(file_path, os.R_OK):
                required_permissions += "r"
            else:
                required_permissions += "-"

            if os.access(file_path, os.W_OK):
                required_permissions += "w"
            else:
                 required_permissions += "-"

            if os.access(file_path, os.X_OK):
                required_permissions += "x"
            else:
                required_permissions += "-"


            recommendations[file_path] = required_permissions
        except OSError as e:
            logging.error(f"Error determining permissions for {file_path}: {e}")

    return recommendations

def compare_to_baseline(recommendations: dict, baseline_file: str) -> dict:
    """
    Compares recommended permissions against a baseline.

    Args:
        recommendations: A dictionary of file paths and recommended permissions.
        baseline_file: Path to a file containing the baseline ACL.

    Returns:
        A dictionary with file paths as keys and notes about differences from the baseline as values.
    """
    differences = {}
    try:
        with open(baseline_file, "r") as f:
            baseline_data = {}
            for line in f:
                file_path, permission = line.strip().split(":")
                baseline_data[file_path] = permission

        for file_path, recommended_permission in recommendations.items():
            if file_path in baseline_data:
                baseline_permission = baseline_data[file_path]
                if recommended_permission != baseline_permission:
                    differences[file_path] = (
                        f"Recommended permission '{recommended_permission}' differs from baseline '{baseline_permission}'"
                    )
            else:
                differences[file_path] = "File not found in baseline."
    except FileNotFoundError:
        logging.error(f"Baseline file {baseline_file} not found.")
    except Exception as e:
        logging.error(f"Error comparing to baseline: {e}")

    return differences

def write_recommendations(
    recommendations: dict, output_file: str, differences: dict = None
):
    """
    Writes permission recommendations to a file.

    Args:
        recommendations: A dictionary of file paths and recommended permissions.
        output_file: The path to the output file.
        differences: Optional dictionary of differences from baseline to include.
    """
    try:
        with open(output_file, "w") as f:
            for file_path, permission in recommendations.items():
                f.write(f"{file_path}:{permission}\n")
            if differences:
                f.write("\n# Differences from baseline:\n")
                for file_path, note in differences.items():
                    f.write(f"# {file_path}: {note}\n")
        console.print(f"Recommendations written to {output_file}")
    except Exception as e:
        logging.error(f"Error writing recommendations to file: {e}")

def display_recommendations(recommendations: dict, differences: dict = None):
     """
     Displays recommendations in a rich table format.
     """
     table = Table(title="Recommended Permissions")

     table.add_column("File Path", style="cyan", no_wrap=True)
     table.add_column("Recommended Permission", style="magenta")
     table.add_column("Baseline Difference", style="yellow")

     for file_path, permission in recommendations.items():
          difference = differences.get(file_path, "") if differences else ""
          table.add_row(file_path, permission, difference)

     console.print(table)

def main():
    """
    Main function to orchestrate the permission assessment process.
    """
    args = setup_argparse()

    user = args.user
    group = args.group
    pid = args.pid
    duration = args.duration
    output_file = args.output
    baseline_file = args.baseline

    # Input validation
    if not isinstance(pid, int) or pid <= 0:
        console.print("[red]Error: Invalid PID.  Please provide a positive integer.[/red]")
        sys.exit(1)

    if not isinstance(duration, int) or duration <= 0:
         console.print("[red]Error: Invalid duration.  Please provide a positive integer.[/red]")
         sys.exit(1)

    if not user:
        console.print("[red]Error: Please specify a user.[/red]")
        sys.exit(1)

    executable_path = get_process_executable_path(pid)
    if executable_path:
        logging.info(f"Monitoring process: {executable_path} (PID: {pid}) for {duration} seconds...")
    else:
        logging.error("Failed to get executable path.  Check PID and permissions.")
        sys.exit(1)


    accessed_files = monitor_file_access(pid, duration)

    if not accessed_files:
        console.print("[yellow]Warning: No file access detected during monitoring. Check the PID and process activity.[/yellow]")

    recommendations = recommend_least_privilege(accessed_files, user, group)

    differences = {}
    if baseline_file:
        differences = compare_to_baseline(recommendations, baseline_file)

    if output_file:
        write_recommendations(recommendations, output_file, differences)
    else:
        display_recommendations(recommendations, differences)


if __name__ == "__main__":
    main()