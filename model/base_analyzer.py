from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseAnalyzer(ABC):
    """Base class for all security analyzers."""
    
    @abstractmethod
    def analyze_content(self, content: str) -> Dict[str, Any]:
        """Analyze content and return security assessment."""
        pass
    
    @abstractmethod
    def get_model_name(self) -> str:
        """Get the name of the model being used."""
        pass
