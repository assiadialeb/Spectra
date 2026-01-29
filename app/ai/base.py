from abc import ABC, abstractmethod

class BaseAIProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, system_instruction: str = None) -> str:
        """
        Generates text based on the given prompt.
        
        Args:
            prompt (str): The main prompt/content.
            system_instruction (str, optional): System level context/persona.
            
        Returns:
            str: The generated text response.
        """
        pass
