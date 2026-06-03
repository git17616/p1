# generate_keys.py
# Pre-generates participant identities for the medical protocol benchmark.
# No actual cryptographic key material needs to be stored for this protocol
# (all keys are derived deterministically from identities at runtime),
# so this file simply writes the identity lists used by run_experiments.py.

import json

IDENTITIES = {
    "proxy": "proxy@example.com",
    "tt": "TT@example.com",
    "doctor": "Doctor@example.com",
}


def generate_patient_identities(n: int) -> list[str]:
    return [f"patient_{i}@example.com" for i in range(1, n + 1)]


def save_identities(n: int, path: str = "identities.json"):
    data = {
        "n": n,
        "patients": generate_patient_identities(n),
        **IDENTITIES,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved {n} patient identities to {path}")


if __name__ == "__main__":
    save_identities(500)
