# Cryptographic Protocol Implementation

This repository contains two cryptographic protocol implementations based on bilinear pairings:

1. **Two-Party AKE Protocol** (`protocol_logic.py`, `server.py`) — An authenticated key exchange between a client and server, with performance experiments.
2. **Three-Party Proxy Re-encryption Protocol** (`three_party_protocol.py`) — A medical data sharing scheme involving a Patient, Proxy, Trusted Third Party (TT), and Doctor.

---

## Prerequisites

### 1. Python
Python 3.8 or higher is recommended.

### 2. System Dependencies (Ubuntu/Debian)
Charm-Crypto requires native C libraries. Install them first:
```bash
sudo apt-get update
sudo apt-get install -y build-essential libgmp-dev libssl-dev python3-dev python3-venv flex bison wget
```

### 3. Install PBC Library
```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xzf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure
make
sudo make install
sudo ldconfig
cd ..
```

> **Windows users:** Use WSL2 with Ubuntu and follow the Linux steps above. Native Windows builds of Charm are not supported.

---

## Setup: Virtual Environment

### Step 1: Create and activate the virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows (WSL):
```bash
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt.

### Step 2: Install Charm-Crypto inside the venv
```bash
git clone https://github.com/JHUISI/charm.git
cd charm
pip install .
cd ..
```

### Step 3: Install remaining Python dependencies
```bash
pip install pycryptodome cryptography numpy matplotlib
```

### Step 4: Verify installation
```bash
python -c "from charm.toolbox.pairinggroup import PairingGroup; print('Charm OK')"
```

---

## Project Structure

```
.
├── protocol_logic.py        # Core two-party AKE protocol logic
├── server.py                # TCP server for the AKE protocol
├── generate_keys.py         # Key generation for clients and server
├── run_experiments.py       # Performance benchmarking and plotting
├── three_party_protocol.py  # Three-party proxy re-encryption protocol
├── server_keys.json         # Generated server keys (created by generate_keys.py)
├── client_keys.json         # Generated client keys (created by generate_keys.py)
├── public_directory.json    # Public key directory (created by generate_keys.py)
└── theory second.txt        # Tamarin prover formal model of the AKE protocol
```

---

## Running the Two-Party AKE Protocol

Make sure the venv is active (`source venv/bin/activate`) before running any command.

### Step 1: Generate Keys
Run once to create keys for 500 clients and the server:
```bash
python generate_keys.py
```

### Step 2: Start the Server
Open a terminal, activate the venv, then run:
```bash
python server.py
```

The server listens on `127.0.0.1:65432`. Keep this terminal open.

### Step 3: Run Experiments
In a second terminal, activate the venv, then run:
```bash
python run_experiments.py
```

This simulates multiple client instances across client counts (`10, 50, 100, 200, 500`), measures AKE time, and saves a plot to `access/ake_time_instances_plot.png`.

---

## Running the Three-Party Protocol

```bash
python three_party_protocol.py
```

This is a standalone script simulating the full flow: Patient → Proxy → TT → Doctor. It prints intermediate values and verifies the final decrypted medical data matches the original.

---

## Deactivating the Virtual Environment

When done:
```bash
deactivate
```

---

## Notes

- `eccp.py` and `aesed.py` are imported in `three_party_protocol.py`. Make sure these files are present in the repo root before running that script.
- The formal security model in `theory second.txt` is written for the [Tamarin Prover](https://tamarin-prover.github.io/).
