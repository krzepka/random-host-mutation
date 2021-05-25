from enum import Enum


class RequestCommand(Enum):
    key = 'key'
    mutation_index = 'm_index'
    var = 'var'
