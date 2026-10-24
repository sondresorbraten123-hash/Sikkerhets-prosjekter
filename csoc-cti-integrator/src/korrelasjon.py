from datetime import datetime
import re
from typing import Any, Dict
from src.database import CTIDatabase

# Regex for å lese brannmurloggen
brannmur_monster = re.compile(
    # Fanger opp tidsstempel
    r"^(?P<tidsstempel>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"
    # spiser opp allow og tcp og mellomrommene
    r"ALLOW\s+TCP\s+"
    # tar inn den interne IPen
    r"(?P<intern-ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+->\s+"
    # Tar inn ekstern IP og Port
    r"(?P<ekstern-ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d+)\s+"
    # Fanger opp bytes sendt
    r"bytes=(?P<bytes>\d+)"
)