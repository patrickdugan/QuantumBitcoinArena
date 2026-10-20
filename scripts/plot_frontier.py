"""Plot the on-chain cost vs off-chain table frontier from results/bench.json.

Run with any Python that has matplotlib, e.g. the Spiral venv:
    Spiral/.venv/Scripts/python.exe scripts/plot_frontier.py
Writes results/frontier.png.
"""
import json
import pathlib

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

root = pathlib.Path(__file__).resolve().parent.parent
doc = json.loads((root / "results" / "bench.json").read_text())
fr = doc["frontier_hash160"]

fig, ax = plt.subplots(figsize=(7.6, 4.8), dpi=140)
colors = {2: "#8c8c8c", 3: "#2b7bba", 4: "#d1495b", 5: "#2f9e6b", 6: "#8a5cc2"}
for k in sorted({r["k"] for r in fr}):
    pts = [r for r in fr if r["k"] == k]
    ax.plot(
        [r["table_bytes_per_bit_16B_labels"] for r in pts],
        [r["marginal_vb_per_bit"] for r in pts],
        "-o",
        color=colors[k],
        label=f"ACW k={k}",
        ms=4,
        lw=1.2,
    )
    for r in pts:
        ax.annotate(f"L={r['l']}", (r["table_bytes_per_bit_16B_labels"], r["marginal_vb_per_bit"]), fontsize=6, xytext=(3, 3), textcoords="offset points")

ax.axhline(17.75, color="k", ls="--", lw=1)
ax.text(70, 17.9, "Lamport (RIPEMD-160): 17.75 vB/bit", fontsize=7)
ax.axhline(3.2, color="#b8860b", ls="--", lw=1)
ax.text(70, 3.3, "Schnorr adaptor (Mosaic today, not PQ): ~3.2 vB/bit", fontsize=7)
ax.axhline(5.8, color="#888", ls=":", lw=1)
ax.text(70, 5.9, "template floor ~5.8 vB/bit (k -> infinity)", fontsize=7)
ax.set_xscale("log")
ax.set_xlabel("off-chain table bytes per message bit (16-byte label per digit bit)")
ax.set_ylabel("on-chain vbytes per message bit (20-byte digests)")
ax.set_title("ACW cost frontier: the on-chain gain flattens while the table grows ~10x per step")
ax.set_ylim(2.5, 19)
ax.grid(alpha=0.25, which="both")
ax.legend(fontsize=7, loc="upper right")
fig.tight_layout()
out = root / "results" / "frontier.png"
fig.savefig(out)
print("wrote", out)
