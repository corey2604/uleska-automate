from dataclasses import dataclass
from typing import Optional
import uuid

@dataclass
class Version:
    id: uuid.UUID
    name: str
    createdDate : str
    schema: Optional[str]
    host: Optional[str]
    port: Optional[int]
    
