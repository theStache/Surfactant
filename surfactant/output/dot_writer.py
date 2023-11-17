# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import networkx as nx
from typing import Optional

import surfactant.plugin
from surfactant.sbomtypes import SBOM


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    """Writes the contents of the SBOM to a DOT file.

    The write_sbom hook for the dot_writer makes a best-effort attempt
    to map the information gathered from the internal SBOM representation
    to a valid Graphvis Dot file.
    Args:
        sbom (SBOM): The SBOM to write to the output file.
        outfile: The output file handle to write the SBOM to.
    """
    # Load JSON data
    data = json.load(SBOM)
    G = nx.DiGraph()
    # Add nodes with attributes
    for software in data['software']:
        node_id = software['UUID']
        node_label = software['name']
        G.add_node(node_id, label=node_label)

    # Add edges based on relationships
    for relationship in data['relationships']:
        xUUID = relationship['xUUID']
        yUUID = relationship['yUUID']
        relationship_type = relationship['relationship']
        G.add_edge(xUUID, yUUID, type=relationship_type)

    # Create a DOT file
    with open(outfile, 'w') as dot_file:
        dot_file.write('digraph G {\n')
        for node_id, attrs in G.nodes(data=True):
            node_label = attrs['label']
            dot_file.write(f'  "{node_id}" [label="{node_label}"];\n')
        for source, target, attrs in G.edges(data=True):
            relationship_type = attrs['type']
            dot_file.write(f'  "{source}" -> "{target}" [label="{relationship_type}"];\n')
        dot_file.write('}\n')
    dot_file.close()


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "dot"
