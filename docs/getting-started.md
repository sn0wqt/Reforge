# Getting Started

Clone and install Reforge locally:

### Using `uv` (Recommended)

```bash
git clone https://github.com/sn0wqt/Reforge.git
cd Reforge
uv sync --extra dev --extra providers
```

### Using standard `pip`

```bash
git clone https://github.com/sn0wqt/Reforge.git
cd Reforge
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
python3 -m pip install -e ".[dev,providers]"
```

## 1. Prepare Ghidra

```bash
ghidra-bridge init
# Edit ghidra-bridge.yaml with the local Ghidra project and target binary path
ghidra-bridge export all
ghidra-bridge build-map
ghidra-bridge info
```

## 2. Initialize Configuration

```bash
reforge init --profile generic-cpp
```

Edit `reforge.yaml` to specify:

- LLM provider and authentication
- `backend.cli_path: ghidra-bridge`
- Source root directory and language standard
- Build and test commands for validation

## 3. Run Reversal

```bash
# Reverse a single function by virtual address
reforge reverse --address 0x401000

# Reverse functions for an entire class
reforge reverse --class CTrain --max-functions 5

# Check parity against existing source
reforge parity --address 0x401000 --strict-exit

# Check progress
reforge status
```

See [README.md](../README.md) for full pipeline details, Android repackaging, and CLI options.
