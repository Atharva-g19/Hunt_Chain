from enum import Enum


class Effect(str, Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"