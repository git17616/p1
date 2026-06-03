# run_experiments.py
# Benchmarks the medical emergency access protocol across varying client counts.

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter

from protocol_logic import MedicalProtocol
from generate_keys import generate_patient_identities

CLIENT_COUNTS = [10, 50, 100, 200, 500]
NUM_INSTANCES = 5

MEDICAL_DATA = b"aes medical data This is my medical data1"

# ── Identities ────────────────────────────────────────────────────────────────

ID_PROXY  = "proxy@example.com"
ID_TT     = "TT@example.com"
ID_DOCTOR = "Doctor@example.com"

# ── Benchmark runner ──────────────────────────────────────────────────────────

def run_instance(n: int) -> dict:
    """Run the full protocol for n patients and return per-phase total times (ms)."""
    proto = MedicalProtocol()
    patients = generate_patient_identities(n)

    totals = {"r1": 0.0, "r2": 0.0, "proxy": 0.0, "tt": 0.0, "doctor": 0.0}

    for pid in patients:
        result = proto.run_full_protocol(
            id_p=pid,
            id_pr=ID_PROXY,
            id_TT=ID_TT,
            id_D=ID_DOCTOR,
            medical_data=MEDICAL_DATA,
        )
        totals["r1"]     += result["r1_ms"]
        totals["r2"]     += result["r2_ms"]
        totals["proxy"]  += result["proxy_ms"]
        totals["tt"]     += result["tt_ms"]
        totals["doctor"] += result["doctor_ms"]

    # Return average per-patient time for this instance
    return {k: v / n for k, v in totals.items()}


# ── Plotting ──────────────────────────────────────────────────────────────────

# Colours and markers matching the example AKE graph style
INSTANCE_COLORS  = ["#1f77b4", "#9467bd", "#2ca02c", "#ff7f0e", "#d62728"]
INSTANCE_MARKERS = ["d", "s", "^", "x", "o"]
AVG_COLOR        = "#c00000"
AVG_MARKER       = "s"


def _apply_axes_style(ax, title: str, n_values: list):
    ax.set_title(title, fontsize=11, pad=8)
    ax.set_xlabel("Number of Clients", fontsize=10)
    ax.set_ylabel("Time (ms)", fontsize=10)
    ax.set_xscale("log")
    ax.set_xticks(n_values)
    ax.xaxis.set_major_formatter(ScalarFormatter())
    ax.tick_params(axis="x", which="minor", bottom=False)
    ax.grid(True, alpha=0.3)


def plot_phase(
    phase_key: str,
    title: str,
    n_values: list,
    instance_matrix: np.ndarray,   # shape (NUM_INSTANCES, len(n_values))
    averages: np.ndarray,
    filename: str,
):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 9))
    fig.subplots_adjust(hspace=0.45)

    # ── Top: all instances ────────────────────────────────────────────────────
    for i in range(NUM_INSTANCES):
        ax1.plot(
            n_values,
            instance_matrix[i],
            marker=INSTANCE_MARKERS[i],
            color=INSTANCE_COLORS[i],
            linewidth=1.2,
            markersize=6,
            label=f"Instance {i + 1}",
        )

    ax1.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.15),
        ncol=NUM_INSTANCES,
        frameon=False,
        fontsize=9,
    )
    _apply_axes_style(ax1, title, n_values)

    # ── Bottom: average ───────────────────────────────────────────────────────
    ax2.plot(
        n_values,
        averages,
        marker=AVG_MARKER,
        color=AVG_COLOR,
        linewidth=1.5,
        markersize=6,
        label="Average",
    )
    ax2.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.15),
        frameon=False,
        fontsize=9,
    )
    _apply_axes_style(
        ax2,
        f"Average {title} of {NUM_INSTANCES} Instances",
        n_values,
    )

    plt.savefig(filename, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved → {filename}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"Medical Protocol Benchmark")
    print(f"Client counts : {CLIENT_COUNTS}")
    print(f"Instances     : {NUM_INSTANCES}\n")

    # Collect results: phase → list of instance rows
    # results[phase][instance_idx][n_idx]
    phases = ["r1", "r2", "proxy", "tt", "doctor"]
    # shape: (NUM_INSTANCES, len(CLIENT_COUNTS)) per phase
    data = {p: np.zeros((NUM_INSTANCES, len(CLIENT_COUNTS))) for p in phases}

    for inst_idx in range(NUM_INSTANCES):
        print(f"── Instance {inst_idx + 1} ──────────────────────────────")
        for n_idx, n in enumerate(CLIENT_COUNTS):
            print(f"  n = {n:>4} ... ", end="", flush=True)
            row = run_instance(n)
            for p in phases:
                data[p][inst_idx][n_idx] = row[p]
            print(
                f"R1={row['r1']:.2f}ms  R2={row['r2']:.2f}ms  "
                f"Proxy={row['proxy']:.2f}ms  TT={row['tt']:.2f}ms  "
                f"Doctor={row['doctor']:.2f}ms"
            )

    print("\nGenerating graphs …")

    graph_specs = [
        ("r1",     "R1 Establishment Time",            "graph_r1_establishment.png"),
        ("r2",     "R2 Establishment Time",            "graph_r2_establishment.png"),
        ("proxy",  "Proxy to Doctor Re-Encryption Time",       "graph_proxy_reencryption.png"),
        ("tt",     "TT to Doctor Re-Encryption Time",          "graph_tt_reencryption.png"),
        ("doctor", "Doctor Medical Data Recovery Time",        "graph_doctor_recovery.png"),
    ]

    for phase_key, title, filename in graph_specs:
        matrix   = data[phase_key]                          # (NUM_INSTANCES, len(CLIENT_COUNTS))
        averages = matrix.mean(axis=0)                      # (len(CLIENT_COUNTS),)
        plot_phase(phase_key, title, CLIENT_COUNTS, matrix, averages, filename)

    print("\nDone.")


if __name__ == "__main__":
    main()
