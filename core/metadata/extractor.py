import os
import json
import yaml
import sqlite3
import hashlib
import magic  # pip install python-magic
import string
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

@dataclass
class ArtifactMetadata:
    filepath: str
    filename: str
    size: int
    mime_type: str
    sha256: str
    file_entropy: float
    content_summary: Dict[str, Any]

class MetadataExtractor:
    def __init__(self):
        self.magic = magic.Magic(mime=True)

    def extract(self, filepath: str) -> Optional[Dict]:
        if not os.path.exists(filepath) or os.path.isdir(filepath):
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

            # --- CONTENT ANALYSIS ROUTING ---
            if "sqlite" in mime or self._is_sqlite(filepath):
                metadata.content_summary = self._analyze_sqlite(filepath)
            
            elif "xml" in mime or filepath.endswith(".xbel") or filepath.endswith(".xml"):
                metadata.content_summary = self._analyze_xml(filepath)
            
            elif "text" in mime or "json" in mime or "yaml" in mime:
                metadata.content_summary = self._analyze_text(filepath)
            
            else:
                # Binary/Unknown fallback
                metadata.content_summary = self._analyze_binary(filepath)

            return asdict(metadata)

        except Exception as e:
            return {
                "filepath": filepath,
                "error": str(e),
                "mime_type": "error"
            }

    def calculate_forensic_score(self, filepath: str) -> float:
        """
        파일의 경로, 확장자, 엔트로피를 기반으로 '포렌식 가치 점수'를 즉시 계산합니다.
        실시간 피드백을 위해 무거운 작업(SHA256 등)은 생략합니다.
        """
        score = 1.0 # 기본 점수 (발견함)
        
        if not os.path.exists(filepath):
            return 0.5 # 생성되었으나 즉시 삭제됨 (Transient) -> 낮은 점수
            
        try:
            # 1. 키워드 분석 (High Value Targets)
            path_lower = filepath.lower()
            high_value_keywords = [
                "history", "login", "password", "credential", "token", "cookie", 
                "session", "preferences", "local state", "wallet", "secret", "key"
            ]
            if any(kw in path_lower for kw in high_value_keywords):
                score += 50.0

            # 2. 확장자/유형 분석 (Structured Data)
            if any(path_lower.endswith(ext) for ext in [".db", ".sqlite", ".json", ".xml", ".conf", ".ini"]):
                score += 20.0
            
            # 3. 엔트로피 분석 (Information Density)
            # 파일 앞부분만 읽어서 빠르게 계산
            entropy = self._calculate_entropy(filepath, limit=2048)
            if entropy > 5.0:
                score += 10.0
            
            return score
            
        except:
            return 1.0 # 에러 시 기본 점수만 부여

    def _get_sha256(self, filepath: str) -> str:
        sha = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(4096):
                    sha.update(chunk)
            return sha.hexdigest()
        except: return "hash_error"

    def _calculate_entropy(self, filepath: str, limi: int = 4096) -> float:
        import math
        try:
            with open(filepath, 'rb') as f:
                data = f.read(limit)
            if not data: return 0.0
            entropy = 0
            for x in range(256):
                p_x = float(data.count(x)) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            return entropy
        except: return 0.0

    def _is_sqlite(self, filepath: str) -> bool:
        try:
            with open(filepath, 'rb') as f:
                return f.read(16) == b'SQLite format 3\x00'
        except: return False

    def _analyze_sqlite(self, filepath: str) -> Dict[str, Any]:
        summary = {"type": "sqlite_db", "tables": []}
        try:
            # Open Read-Only
            conn = sqlite3.connect(f"file:{filepath}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            for table in cursor.fetchall():
                t_name = table[0]
                cursor.execute(f"PRAGMA table_info({t_name})")
                cols = [c[1] for c in cursor.fetchall()]
                summary["tables"].append(f"{t_name} {cols}")
            conn.close()
        except Exception as e:
            summary["error"] = str(e)
        return summary

    def _analyze_xml(self, filepath: str) -> Dict[str, Any]:
        """
        Parses XML/XBEL to give the LLM structural context.
        Perfect for history files, configs, and UI definitions.
        """
        summary = {"type": "xml_structure"}
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            summary["root_tag"] = root.tag
            
            # Extract top-level children tags to define structure
            children = [child.tag for child in root][:10]
            summary["children_tags"] = list(set(children)) # Deduplicate
            
            # Sample text content (e.g., bookmark URLs)
            text_samples = []
            for elem in root.iter():
                if elem.text and len(elem.text.strip()) > 3:
                    text_samples.append(elem.text.strip())
                if 'href' in elem.attrib:
                    text_samples.append(elem.attrib['href'])
                if len(text_samples) > 5: break
            
            summary["samples"] = text_samples
        except Exception as e:
            summary["error"] = f"XML Parse Error: {e}"
            # Fallback to text analysis if XML fails
            return self._analyze_text(filepath)
        return summary

    def _analyze_text(self, filepath: str) -> Dict[str, Any]:
        """
        Reads the actual content of text files.
        """
        summary = {"type": "text_content"}
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(2048) # Read first 2KB
            
            # 1. Try JSON
            try: 
                js = json.loads(content)
                summary["structure"] = "json"
                summary["keys"] = list(js.keys()) if isinstance(js, dict) else "list"
                return summary
            except: pass

            # 2. Plain Text Sampling
            lines = content.splitlines()
            summary["head"] = lines[:10]
            
            # 3. Keyword Detection (Forensic Hints)
            hints = []
            if "http" in content: hints.append("urls")
            if "/" in content: hints.append("paths")
            if "Forensic" in content: hints.append("user_created_content")
            summary["detected_features"] = hints
            
        except Exception as e:
            summary["error"] = str(e)
        return summary

    def _analyze_binary(self, filepath: str) -> Dict[str, Any]:
        summary = {"type": "binary"}
        try:
            # Extract printable strings (like the unix 'strings' command)
            with open(filepath, "rb") as f:
                data = f.read(4096)
                chars = []
                for byte in data:
                    if 32 <= byte <= 126:
                        chars.append(chr(byte))
                    else:
                        chars.append(' ')
                strings = "".join(chars).split()
                # Filter for meaningful length
                summary["strings"] = [s for s in strings if len(s) > 4][:20]
        except: pass
        return summary