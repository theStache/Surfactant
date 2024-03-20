# Ghidra BSim Plugin for SBOM Surfactant

A plugin for Surfactant that uses the
[binary2strings](https://github.com/glmcdona/binary2strings)
Ghidra BSim to extract function signatures from ELF and PE files.

## Quickstart

In the same virtual environment that Surfactant was installed in, install this plugin with `pip install .`.

For developers making changes to this plugin, install it with `pip install -e .`.

After installing the plugin, run Surfactant to generate an SBOM as usual and entries for ELF
and PE files will generate additional json files in the working directory that contain the strings of those files.

Modify the `config.txt` file to provide the correct location for your Ghidra installation and project name.

Example:
Output Filename: `signature_output.mv.db`

Surfactant features for controlling which plugins are enabled/disabled can be used to control
whether or not this plugin will run using the plugin name `surfactantplugin-binary2strings` (the name given in
`pyproject.toml` under the `project.entry-points."surfactant"` section).

## Uninstalling

The plugin can be uninstalled with `pip uninstall surfactantplugin-binary2strings`.
