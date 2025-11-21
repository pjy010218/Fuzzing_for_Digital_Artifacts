import os
import json
import logging
import requests
import google.generativeai as genai
from .prompts import D3FEND_SYSTEM_PROMPT, ARTIFACT_USER_PROMPT

class LLMClient:
    def __init__(self, provider="ollama"):
        # Sanitize input (lowercase, remove spaces)
        self.provider = provider.lower().strip()
        self.logger = logging.getLogger("LLMClient")
        
        # Default values to prevent AttributeError
        self.model_name = "llama3.2" 
        self.api_url = "http://localhost:11434/api/generate"

        if self.provider == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                # Fallback to printing error but don't crash immediately
                self.logger.error("GEMINI_API_KEY not found.")
            else:
                genai.configure(api_key=api_key)
                # Use the specific model version to avoid 404s
                self.model = genai.GenerativeModel("gemini-1.5-flash-001")
            
        elif self.provider == "ollama":
            self.api_url = "http://localhost:11434/api/generate"
            self.model_name = "llama3.2" 

    def generate(self, system_prompt, user_prompt):
        full_prompt = f"{system_prompt}\n\n{user_prompt}"

        if self.provider == "gemini":
            try:
                response = self.model.generate_content(full_prompt)
                text = response.text.strip()
                if text.startswith("```json"):
                    text = text[7:-3]
                return text
            except Exception as e:
                self.logger.error(f"Gemini Error: {e}")
                return "{}"

        elif self.provider == "ollama":
            try:
                payload = {
                    "model": self.model_name,
                    "prompt": full_prompt,
                    "format": "json",
                    "stream": False
                }
                resp = requests.post(self.api_url, json=payload)
                resp.raise_for_status()
                return resp.json().get("response", "{}")
            except Exception as e:
                self.logger.error(f"Ollama Error: {e}")
                return "{}"
        
        return "{}"

class D3FENDMapper:
    def __init__(self, provider="ollama"):
        self.client = LLMClient(provider=provider)
        self.logger = logging.getLogger("D3FENDMapper")

    def classify_artifact(self, app_name, artifact_data):
        filepath = artifact_data['filepath']
        metadata = artifact_data['metadata']

        # Metadata cleaning
        if isinstance(metadata, dict) and 'strings_preview' in metadata:
            if len(metadata['strings_preview']) > 500:
                 metadata['strings_preview'] = str(metadata['strings_preview'])[:500] + "..."

        prompt = ARTIFACT_USER_PROMPT.format(
            app_name=app_name,
            filepath=filepath,
            metadata_json=json.dumps(metadata, indent=2)
        )

        try:
            response_str = self.client.generate(D3FEND_SYSTEM_PROMPT, prompt)
            result = json.loads(response_str)
            return result
        except Exception as e:
            self.logger.error(f"Parsing failed for {filepath}")
            return {
                "d3fend_id": "DA0000", 
                "d3fend_label": "Classification Error", 
                "confidence": 0.0, 
                "reasoning": "JSON Parsing Failed or LLM Error"
            }