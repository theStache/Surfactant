# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from pathlib import Path
import angr
import surfactant.plugin

@surfactant.plugin.hookimpl
def angrimport_finder(filename: str, filetype: str, metadata:dict):
    """
    Extract list of imported function from a binary file using angr.
    :param filename (str): The full path to the file.
    :param filetype (str): File type information based on magic bytes.
    """
    # Only parse executable files
    if filetype not in ["ELF", "PE"]:
        pass

    print("angr import extraction {}".format(filename))
    filename = Path(filename)

    if not filename.exists():
        raise FileNotFoundError(f"No such file: '{filename}'")
    try:
        import_dict = {}
        import_dict["imported functions"] = []

        # Create an angr project
        project = angr.Project(filename._str, auto_load_libs=False)

        # Get the imported functions using symbol information
        for symbol in project.loader.main_object.symbols:
            if symbol.is_function:
                import_dict["imported functions"].append(symbol.name)

        return metadata.metadata.append(import_dict)
    except Exception as e:
        print("Angr Error {} {}".format(filename._str, e))