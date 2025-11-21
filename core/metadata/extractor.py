import os
import json
import yaml
import sqlite3
import hashlib
import magic  # Requires: pip install python-magic
import string
import struct
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

@dataclass
class ArtifactMetadata:
    filepath: str
    filename: str
    size: int
    mime_type: str
    sha256: str
    file_entropy: float  # Good for detecting encrypted/packed files
    content_summary: Dict[str, Any] # The "DNA" for the LLM

class MetadataExtractor:
    def __init__(self):
        self.magic = magic.Magic(mime=True)

    def extract(self, filepath: str) -> Optional[Dict]:
        """
        Main entry point. Analyzes a file and returns a JSON-serializable dict
        ready for the LLM prompt.
        """
        if not os.path.exists(filepath):
            return None

        try:
            stat = os.stat(filepath)
            mime = self.magic.from_file(filepath)
            
            metadata = ArtifactMetadata(
                filepath=filepath,
                filename=os.path.basename(filepath),
                size=stat.st_size,
                mime_type=mime,
                sha256=self._get_sha256(filepath),
                file_entropy=self._calculate_entropy(filepath),
                content_summary={}
            )

            # Strategy Pattern for content extraction
            if "sqlite" in mime or self._is_sqlite(filepath):
                metadata.content_summary = self._analyze_sqlite(filepath)
            elif "text" in mime or "json" in mime or "xml" in mime:
                metadata.content_summary = self._analyze_text(filepath, mime)
            elif "application/x-sharedlib" in mime or "application/x-executable" in mime:
                metadata.content_summary = self._analyze_binary(filepath)
            else:
                # Fallback for unknown blobs
                metadata.content_summary = {"preview": "Binary data", "strings": self._extract_strings(filepath)}

            return asdict(metadata)

        except Exception as e:
            return {
                "filepath": filepath,
                "error": str(e),
                "mime_type": "error/access-denied"
            }

    def _get_sha256(self, filepath: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _calculate_entropy(self, filepath: str) -> float:
        # Quick entropy calc to detect encryption/compression
        import math
        with open(filepath, 'rb') as f:
            data = f.read(4096) # Sample first 4KB
        if not data: return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _is_sqlite(self, filepath: str) -> bool:
        # Standard magic sometimes misses SQLite if extension is weird
        with open(filepath, 'rb') as f:
            header = f.read(16)
        return header == b'SQLite format 3\x00'

    def _analyze_sqlite(self, filepath: str) -> Dict[str, Any]:
        """
        Crucial for D3FEND: Extracts table names and column names.
        This allows LLM to map 'cookies' table -> Browser Artifact.
        """
        summary = {"type": "sqlite_database", "tables": []}
        try:
            # Open in Read-Only mode (URI) to prevent locking/modifying
            conn = sqlite3.connect(f"file:{filepath}?mode=ro", uri=True)
            cursor = conn.cursor()
            
            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            for table_name in tables:
                t_name = table_name[0]
                # Get columns for this table
                cursor.execute(f"PRAGMA table_info({t_name})")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Sample data (first row) to give LLM context
                cursor.execute(f"SELECT * FROM {t_name} LIMIT 1")
                sample = cursor.fetchone()
                
                summary["tables"].append({
                    "name": t_name,
                    "columns": columns,
                    "sample_row": str(sample)[:200] # Truncate for token limits
                })
            conn.close()
        except Exception as e:
            summary["error"] = f"SQLite parsing failed: {str(e)}"
        return summary

    def _analyze_text(self, filepath: str, mime: str) -> Dict[str, Any]:
        """Handles JSON, YAML, INI, and plain text logs."""
        summary = {"type": "text_content"}
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()

            # Try JSON
            try:
                data = json.loads(content)
                summary["structure"] = "json"
                # Extract top-level keys only (privacy + token economy)
                if isinstance(data, dict):
                    summary["keys"] = list(data.keys())
                return summary
            except json.JSONDecodeError:
                pass

            # Try YAML (common for configs)
            try:
                # Safe load to avoid code execution vulnerabilities
                data = yaml.safe_load(content) 
                if isinstance(data, dict):
                    summary["structure"] = "yaml"
                    summary["keys"] = list(data.keys())
                    return summary
            except:
                pass

            # Fallback: Text sampling
            lines = content.splitlines()
            summary["line_count"] = len(lines)
            summary["head"] = lines[:5]
            summary["tail"] = lines[-5:]
            
            # Look for common tokens
            if "http://" in content or "https://" in content:
                summary["detected_features"] = ["urls"]
            if "/" in content and bin(0) not in content:
                summary["detected_features"] = ["file_paths"]
                
        except Exception as e:
            summary["error"] = str(e)
            
        return summary

    def _analyze_binary(self, filepath: str) -> Dict[str, Any]:
        """Simple introspection for executables/libraries."""
        summary = {"type": "binary_elf"}
        # Extract strings (simplest way to find URLs/IPs/paths in binary)
        summary["strings_preview"] = self._extract_strings(filepath, min_len=6, limit=20)
        return summary

    def _extract_strings(self, filepath: str, min_len=4, limit=50) -> List[str]:
        """Equivalent to Linux 'strings' command."""
        with open(filepath, "rb") as f:
            result = ""
            found = []
            for byte in f.read():
                char = chr(byte)
                if char in string.printable:
                    result += char
                    continue
                if len(result) >= min_len:
                    found.append(result)
                    if len(found) >= limit:
                        break
                result = ""
        return found

# --- USAGE EXAMPLE ---
if __name__ == "__main__":
    # Create a dummy sqlite for testing
    db_path = "/tmp/test_artifact.db"
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS user_visits (id INTEGER, url TEXT, timestamp INTEGER)")
    c.execute("INSERT INTO user_visits VALUES (1, 'https://google.com', 1678889)")
    conn.commit()
    conn.close()

    extractor = MetadataExtractor()
    result = extractor.extract(db_path)
    print(json.dumps(result, indent=2))