"""Flowchart for the decryption process, showing how the encrypted file is parsed, ephemeral data is recovered with RSA, parameters are decrypted with AES-GCM, classical ciphers are reversed, and integrity is verified."""

import graphviz


def render_decryption_flowchart() -> graphviz.Digraph:
    """Return a Graphviz digraph representing the decryption process flowchart."""
    dot = graphviz.Digraph(comment="Decryption Process")

    # Use a top-down orientation
    dot.attr(rankdir="TB")

    # Define nodes (using standard flowchart shapes)
    dot.node("A", "Start", shape="ellipse")
    dot.node("B", "Read Encrypted Data", shape="parallelogram")
    dot.node("C", "Parse Ephemeral Data, Param Ciphertext,\nand Final Ciphertext", shape="rectangle",)
    dot.node("D", "RSA Decrypt Ephemeral Data\n(Recover AES Key & IV)", shape="rectangle")
    dot.node("E", "AES-GCM Decrypt Parameters\n(using Tag)", shape="rectangle")
    dot.node("F", "Validate Parameter Integrity", shape="rectangle")
    dot.node("G", "Apply Vernam Cipher (Reverse)", shape="rectangle")
    dot.node("H", "Apply Vigenere Cipher (Reverse)", shape="rectangle")
    dot.node("I", "Apply Polyalphabetic Cipher (Reverse)", shape="rectangle")
    dot.node("J", "Apply Monoalphabetic Cipher (Reverse)", shape="rectangle")
    dot.node("K", "Apply Transposition Cipher (Reverse)", shape="rectangle")
    dot.node("L", "Verify Data Hash", shape="rectangle")
    dot.node("M", "Write Decrypted Output", shape="parallelogram")
    dot.node("N", "End", shape="ellipse")

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

    return dot


if __name__ == "__main__":
    # Render the flowchart as a file, e.g. PNG
    flowchart = render_decryption_flowchart()
    flowchart.render(
        filename="decryption_flowchart",
        directory="assets",
        format="svg",
        cleanup=True,
    )
