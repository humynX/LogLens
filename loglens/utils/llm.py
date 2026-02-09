"""
LogLens - LLM Interface
========================
Unified interface for local and cloud LLMs.
Supports Ollama (local), Groq (fast), and OpenAI (fallback).

Author: HUMYNX Team
"""

import os
import re
import json
import logging
import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from abc import ABC, abstractmethod

logger = logging.getLogger("loglens.llm")


@dataclass
class LLMConfig:
    """LLM configuration."""
    # Local (Ollama)
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    
    # Groq (fast, free tier)
    groq_api_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"
    
    # OpenAI (fallback)
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    
    # Behavior
    timeout: int = 30
    max_retries: int = 2
    temperature: float = 0.0  # Deterministic outputs for consistent results
    max_tokens: int = 2000
    
    def __post_init__(self):
        # Load from environment if not set
        if not self.groq_api_key:
            self.groq_api_key = os.environ.get("GROQ_API_KEY", "")
        if not self.openai_api_key:
            self.openai_api_key = os.environ.get("OPENAI_API_KEY", "")


class LLMProvider(ABC):
    """Abstract LLM provider."""
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> Optional[str]:
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass


class OllamaProvider(LLMProvider):
    """Local Ollama LLM provider."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self._available = None
    
    @property
    def name(self) -> str:
        return f"ollama:{self.config.ollama_model}"
    
    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        
        try:
            resp = requests.get(
                f"{self.config.ollama_url}/api/tags",
                timeout=3
            )
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                for m in models:
                    model_name = m.get("name", "").split(":")[0]
                    if self.config.ollama_model in model_name or model_name in self.config.ollama_model:
                        self._available = True
                        return True
        except:
            pass
        
        self._available = False
        return False
    
    def generate(self, prompt: str, **kwargs) -> Optional[str]:
        if not self.is_available():
            return None
        
        try:
            response = requests.post(
                f"{self.config.ollama_url}/api/generate",
                json={
                    "model": self.config.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": kwargs.get("temperature", self.config.temperature),
                        "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
                    }
                },
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                return response.json().get("response", "")
        except Exception as e:
            logger.warning(f"Ollama error: {e}")
        
        return None


class GroqProvider(LLMProvider):
    """Groq cloud LLM provider (fast, free tier available)."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self._available = None
    
    @property
    def name(self) -> str:
        return f"groq:{self.config.groq_model}"
    
    def is_available(self) -> bool:
        return bool(self.config.groq_api_key)
    
    def generate(self, prompt: str, **kwargs) -> Optional[str]:
        if not self.is_available():
            return None
        
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.config.groq_api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.config.groq_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": kwargs.get("temperature", self.config.temperature),
                    "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
                },
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"Groq error: {e}")
        
        return None


class OpenAIProvider(LLMProvider):
    """OpenAI cloud LLM provider (fallback)."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
    
    @property
    def name(self) -> str:
        return f"openai:{self.config.openai_model}"
    
    def is_available(self) -> bool:
        return bool(self.config.openai_api_key)
    
    def generate(self, prompt: str, **kwargs) -> Optional[str]:
        if not self.is_available():
            return None
        
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.config.openai_api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.config.openai_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": kwargs.get("temperature", self.config.temperature),
                    "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
                },
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"OpenAI error: {e}")
        
        return None


class LLMInterface:
    """
    Unified LLM interface with automatic fallback.
    
    Priority:
    1. Ollama (local, free, private)
    2. Groq (fast, free tier)
    3. OpenAI (fallback)
    """
    
    def __init__(self, config: LLMConfig = None):
        self.config = config or LLMConfig()
        
        # Initialize providers in priority order
        self.providers: List[LLMProvider] = [
            OllamaProvider(self.config),
            GroqProvider(self.config),
            OpenAIProvider(self.config),
        ]
        
        self._active_provider = None
        self._stats = {
            "calls": 0,
            "successes": 0,
            "failures": 0,
            "tokens_used": 0,
        }
    
    @property
    def is_available(self) -> bool:
        """Check if any LLM is available."""
        return any(p.is_available() for p in self.providers)
    
    @property
    def active_provider_name(self) -> str:
        """Get the name of the active provider."""
        for p in self.providers:
            if p.is_available():
                return p.name
        return "none"
    
    def generate(self, prompt: str, **kwargs) -> Optional[str]:
        """
        Generate response using available LLM.
        Automatically falls back through providers.
        """
        self._stats["calls"] += 1
        
        for provider in self.providers:
            if provider.is_available():
                result = provider.generate(prompt, **kwargs)
                if result:
                    self._stats["successes"] += 1
                    self._active_provider = provider.name
                    return result
        
        self._stats["failures"] += 1
        return None
    
    def parse_json(self, response: str) -> Optional[Dict]:
        """
        Parse JSON from an existing LLM response string.
        Use this when you already have the response and don't want another LLM call.
        """
        if not response:
            return None
        
        response = response.strip()
        
        def fix_regex_escapes(s: str) -> str:
            """Fix common regex escape issues in JSON strings."""
            result = []
            i = 0
            while i < len(s):
                if s[i] == '\\' and i + 1 < len(s):
                    next_char = s[i + 1]
                    if next_char in '\\"bfnrtu/':
                        result.append(s[i:i+2])
                        i += 2
                    elif next_char in 'dswDSW+*?.|^$[](){}':
                        result.append('\\\\')
                        result.append(next_char)
                        i += 2
                    elif next_char == '\\':
                        result.append('\\\\')
                        i += 2
                    else:
                        result.append('\\\\')
                        result.append(next_char)
                        i += 2
                else:
                    result.append(s[i])
                    i += 1
            return ''.join(result)
        
        def try_parse(s: str) -> Optional[Dict]:
            s = s.strip()
            if not s:
                return None
            try:
                result = json.loads(s)
                if isinstance(result, dict):
                    return result
            except:
                pass
            try:
                fixed = fix_regex_escapes(s)
                result = json.loads(fixed)
                if isinstance(result, dict):
                    return result
            except:
                pass
            return None
        
        # Strategy 1: Direct parse
        result = try_parse(response)
        if result:
            return result
        
        # Strategy 2: Extract from markdown code blocks
        code_block_patterns = [
            r'```json\s*\n?([\s\S]*?)\n?\s*```',
            r'```\s*\n?([\s\S]*?)\n?\s*```',
        ]
        
        for pattern in code_block_patterns:
            matches = re.findall(pattern, response, re.MULTILINE)
            for match in matches:
                result = try_parse(match)
                if result:
                    return result
        
        # Strategy 3: Find JSON object by matching braces
        # Use a simpler approach - find first { and use json.loads with incremental substring
        start_idx = response.find('{')
        if start_idx != -1:
            # Try progressively longer substrings until we get valid JSON
            for end_idx in range(len(response) - 1, start_idx, -1):
                if response[end_idx] == '}':
                    json_str = response[start_idx:end_idx + 1]
                    result = try_parse(json_str)
                    if result:
                        return result
        
        return None
    
    def generate_json(self, prompt: str, **kwargs) -> Optional[Dict]:
        """
        Generate and parse JSON response.
        Makes ONE LLM call and parses the result.
        """
        response = self.generate(prompt, **kwargs)
        if not response:
            logger.warning("LLM returned empty response")
            return None
        
        result = self.parse_json(response)
        if not result:
            # Detailed debugging
            logger.warning(f"Failed to parse JSON from LLM response: {response[:200]}...")
            logger.debug(f"Response length: {len(response)}")
            logger.debug(f"First char: {repr(response[0]) if response else 'N/A'}")
            logger.debug(f"Last char: {repr(response[-1]) if response else 'N/A'}")
            # Try to identify the issue
            import json
            try:
                json.loads(response)
            except json.JSONDecodeError as e:
                logger.debug(f"JSON decode error: {e}")
        return result
    
    def get_stats(self) -> Dict:
        """Get usage statistics."""
        return {
            **self._stats,
            "active_provider": self.active_provider_name,
            "providers_available": [p.name for p in self.providers if p.is_available()],
        }


# Global instance for convenience
_default_llm: Optional[LLMInterface] = None


def get_llm(config: LLMConfig = None) -> LLMInterface:
    """Get or create default LLM interface."""
    global _default_llm
    if _default_llm is None or config is not None:
        _default_llm = LLMInterface(config)
    return _default_llm
