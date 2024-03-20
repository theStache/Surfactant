import json
from pathlib import Path

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
import subprocess

dirs = {
    'GHIDRA': None,
    'PROJ': None,
    'DATABASE': None,
    'XML_DIR': None,
}

with open('config.txt', 'r') as f:
    lines = f.readlines()
    for line in lines:
        # Split the line into key and value parts
        parts = line.split('=')
        if len(parts) == 2:
            key = parts[0].strip()  # Remove leading/trailing whitespace from the key
            value = parts[1].strip()  # Remove leading/trailing whitespace from the value
            if key in dirs:
                dirs[key] = value  # Update the dictionary if the key is recognized

# Print the updated dirs to verify the results
for key, value in dirs.items():
    print(f"{key}: {value}")


def pass_to_ghidra(filename=str):
    filename = Path(filename)

    #cd <ghidra_install_dir>/support
    #./analyzeHeadless <ghidra_project_dir> postgres_object_files -import ~/postgres_object_files/*

    # Define the paths and parameters for the Ghidra headless command
    ghidra_path = dirs["GHIDRA"]+"/support/analyzeHeadless"
    project_dir = dirs['PROJ']
    project_name = "project_name"
    binary_path = filename
    # Ensure you replace the above paths with the actual paths on your system

    # Construct the command to run Ghidra in headless mode
    command = [
        ghidra_path,
        project_dir,
        project_name,
        "-import",
        binary_path
    ]

    # Run the command
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"Ghidra analysis completed successfully. Output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error running Ghidra analysis: {e}\nOutput:\n{e.stdout}\nError Output:\n{e.stderr}")


def pass_to_bsim():
    #./bsim generatesigs ghidra:/<ghidra_project_dir>/postgres_object_files --bsim file:/<database_dir>/example ~/bsim_sigs
    command = [
        f"{dirs["GHIDRA"]}/support/bsim",
        "generatesigs",
        f"ghidra:{dirs['PROJ']}"
        f"bsim=file:{dirs['DATABASE']}",
        f"{dirs['XML_DIR']}"
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"BSim generatesigs completed successfully. Output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error running BSim analysis: {e}\nOutput:\n{e.stdout}\nError Output:\n{e.stderr}")


def commit_to_db():
    command = [
        f"{dirs["GHIDRA"]}/support/bsim",
        "commitsigs",
        f"file:{dirs['DATABASE']}",
        f"{dirs['XML_DIR']}"
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"BSim commitsigs completed successfully. Output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error running BSim analysis: {e}\nOutput:\n{e.stdout}\nError Output:\n{e.stderr}")


@surfactant.plugin.hookimpl(specname="ghidra_bsim_info")
def ghidra_analysis(filename: str, filetype: str):
    """
    Extract function signatures from a binary file using Ghidra BSim.
    :param filename (str): The full path to the file to extract information from.
    :param filetype (str): File type information based on magic bytes.
    """
    if filetype not in ["ELF", "PE", "BIN"]:
    pass

    pass_to_ghidra()
    pass_to_bsim()
    commit_to_db()
