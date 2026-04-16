"""Split OUI data fragments."""

from .part_1 import OUI_DATA as PART_1
from .part_2 import OUI_DATA as PART_2
from .part_3 import OUI_DATA as PART_3
from .part_4 import OUI_DATA as PART_4

OUI_DATA_PARTS = (PART_1, PART_2, PART_3, PART_4)

__all__ = ['OUI_DATA_PARTS']