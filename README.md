# DynArtifact: Dynamic Artifact Discovery via Fuzzing & LLM-Based D3FEND Mapping
<br>
DynArtifact is a novel forensic research system that automates the discovery of digital artifacts (files, logs, databases) created by user-space applications.<br>
<br>

Unlike traditional static analysis or vulnerability fuzzers, DynArtifact uses Behavioral Fuzzing to induce state changes in a target application (GUI or CLI) and employs eBPF (Extended Berkeley Packet Filter) to trace the resulting filesystem footprint. Discovered artifacts are then semantically analyzed and classified into the MITRE D3FEND Digital Artifact Ontology using Large Language Models (LLM).<br>
<br>

### Behavioral Fuzzing vs. Crash Fuzzing:
Instead of trying to crash the application, the fuzzing engine aims to maximize "State Coverage" (opening menus, clicking buttons, triggering saves) to force file I/O.<br>
<br>
### Kernel-Level Observability: 
Uses eBPF (via BCC) to trace openat, write, and unlink syscalls with low overhead, bypassing user-space anti-debugging tricks.<br>
<br>
### Semantic Ontology Mapping: 
Bridges the gap between raw file paths and forensic meaning. An LLM (Gemini/Llama) analyzes file metadata (schema, entropy, headers) to label artifacts (e.g., mapping Cookies.sqlite to DA0011: Browser Information).<br>
<br>
### Knowledge Graph Architecture: 
Stores relationships (App -> Spawns -> Process -> Writes -> Artifact) in a Neo4j graph database for complex forensic querying.<br>
<br>

## System Architecture
The system is composed of four modular layers:<br>

1. **Orchestrator:** Manages the lifecycle of the application, the headless X11 display, and the fuzzing threads.
2. **Tracer (Physical Layer):** eBPF probes hook into the Linux kernel to capture file operations in real-time.
3. **Graph Store (Storage Layer):** A Neo4j database that deduplicates events and models the "Genealogy" of artifacts.
4. **Cognitive Layer:** A Python-based pipeline that feeds artifact metadata to an LLM (Ollama or Gemini) for classification.

<br>
<br>
### System Requirements
OS: Linux (Ubuntu 22.04/24.04 recommended) <br>
Kernel: 5.4+ (with BTF support for eBPF) <br>
Root Privileges: Required for eBPF injection. <br>
Dependencies: Docker (for Neo4j), Xvfb, Fluxbox. <br>
AI Provider: OLLAMA (LLAMA 3.2) <br>
