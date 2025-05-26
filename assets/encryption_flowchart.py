"""Flowchart for the encryption process, showing classical cipher layering, parameter hashing, envelope encryption, and final file output structure."""

import graphviz


def render_encryption_flowchart() -> graphviz.Digraph:
    """Return a Graphviz digraph representing the encryption process flowchart."""
    dot = graphviz.Digraph(comment="Encryption Process")

    # Use a top-down orientation
    dot.attr(rankdir="TB")

    # Define nodes (using standard flowchart shapes)
    dot.node("A", "Start", shape="ellipse")
    dot.node("B", "Read Plaintext Data", shape="parallelogram")
    dot.node("C", "Apply Transposition Cipher", shape="rectangle")
    dot.node("D", "Apply Monoalphabetic Cipher", shape="rectangle")
    dot.node("E", "Apply Polyalphabetic Cipher", shape="rectangle")
    dot.node("F", "Apply Vigenere Cipher", shape="rectangle")
    dot.node("G", "Apply Vernam Cipher", shape="rectangle")
    dot.node("H", "Compute Data Hash", shape="rectangle")
    dot.node("I", "Serialize & Prepare Cipher Parameters", shape="rectangle")
    dot.node("J", "Generate Ephemeral Key & IV", shape="rectangle")
    dot.node("K", "Encrypt Parameters with AES-GCM\n(Tag Produced)", shape="rectangle")
    dot.node("L", "Encrypt Ephemeral Data with RSA", shape="rectangle")
    dot.node("M", "Assemble Final Output Structure\n(including ciphertext,\nRSA-wrapped data, param ciphertext)", shape="rectangle",)
    dot.node("N", "Write Encrypted Output", shape="parallelogram")
    dot.node("O", "End", shape="ellipse")

    # Define edges
    dot.edge("A", "B")
    dot.edge("B", "C")
    dot.edge("C", "D")
    dot.edge("D", "E")
    dot.edge("E", "F")
    dot.edge("F", "G")
    dot.edge("G", "H")
    dot.edge("H", "I")
    dot.edge("I", "J")
    dot.edge("J", "K")
    dot.edge("K", "L")
    dot.edge("L", "M")
    dot.edge("M", "N")
    dot.edge("N", "O")

    return dot


if __name__ == "__main__":
    # Render the flowchart as a file, e.g. PNG
    flowchart = render_encryption_flowchart()
    flowchart.render(
        filename="encryption_flowchart",
        directory="assets",
        format="svg",
        cleanup=True,
    )
