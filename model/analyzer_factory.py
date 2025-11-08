from typing import Type, Dict, Any
from .base_analyzer import BaseAnalyzer
from .gemini_analyzer import GeminiAnalyzer
from .openai_analyzer import OpenAIAnalyzer
from .claude_analyzer import ClaudeAnalyzer
from .grok_analyzer import GrokLlamaAnalyzer  # ✅ new import

class AnalyzerFactory:
    """Factory class to create and manage different analyzer instances."""

    _ANALYZERS = {
        'gemini': GeminiAnalyzer,
        'openai': OpenAIAnalyzer,
        'claude': ClaudeAnalyzer,
        'grok': GrokLlamaAnalyzer,  # ✅ new analyzer
    }

    @classmethod
    def create_analyzer(cls, analyzer_type: str, **kwargs) -> BaseAnalyzer:
        """
        Create an analyzer instance by type.

        Args:
            analyzer_type: One of 'gemini', 'openai', 'claude', or 'grok'
            **kwargs: Additional arguments to pass to the analyzer

        Returns:
            An instance of the specified analyzer

        Raises:
            ValueError: If the analyzer type is not supported
        """
        analyzer_class = cls._ANALYZERS.get(analyzer_type.lower())
        if not analyzer_class:
            raise ValueError(
                f"Unsupported analyzer type: {analyzer_type}. "
                f"Available types: {', '.join(cls._ANALYZERS.keys())}"
            )
        return analyzer_class(**kwargs)

    @classmethod
    def list_available_analyzers(cls) -> Dict[str, Type[BaseAnalyzer]]:
        """Get a dictionary of available analyzer types and their classes."""
        return cls._ANALYZERS.copy()

    @classmethod
    def get_analyzer_config(cls, analyzer_type: str) -> Dict[str, Any]:
        """Get default configuration for an analyzer type."""
        configs = {
            'gemini': {
                'model': 'gemini-1.5-flash',
                'env_var': 'GOOGLE_API_KEY',
                'description': 'Google Gemini model for security analysis',
            },
            'openai': {
                'model': 'gpt-4',
                'env_var': 'OPENAI_API_KEY',
                'description': 'OpenAI models for security analysis',
            },
            'claude': {
                'model': 'claude-3-sonnet-20240229',
                'env_var': 'ANTHROPIC_API_KEY',
                'description': 'Anthropic Claude model for security analysis',
            },
            'grok': {
                'model': 'grok-llama-3.1-8b-instant',
                'env_var': 'GROK_API_KEY',
                'description': 'Grok / LLaMA 3.1 instant model for security analysis',
            },
        }
        return configs.get(analyzer_type.lower(), {})
