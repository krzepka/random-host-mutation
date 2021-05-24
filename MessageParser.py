from abc import ABC, abstractmethod
from enum import Enum


class MessageCommand(Enum):
    get_shared_key = 1  # retrieve shared_key from MTC
    authorize_packet = 2  # send packet to MTC, it should accept or reject that packet
    get_mutation_index = 3  # retrieve mutation_index from MTC for host h_i
    get_var = 4  # retrieve VAR from MTC for host h_i


class MessageType(Enum):
    request = 1
    response = 2


class MessageParser:
    def __init__(self):
        pass

    def parse(self):
        pass


class Factory(ABC):
    @abstractmethod
    def create(self):
        pass


class RequestFactory(Factory):
    def __init__(self, command, args):
        self.command = command
        self.args = args

    def create(self):
        message = ""
        if self.command is MessageCommand.get_shared_key:
            pass
        elif self.command is MessageCommand.authorize_packet:
            pass
        elif self.command is MessageCommand.get_mutation_index:
            pass
        elif self.command is MessageCommand.get_var:
            pass

        return message


class ResponseFactory(Factory):
    def __init__(self, command, args):
        self.command = command
        self.args = args

    def create(self):
        message = ""
        if self.command is MessageCommand.get_shared_key:
            pass
        elif self.command is MessageCommand.authorize_packet:
            pass
        elif self.command is MessageCommand.get_mutation_index:
            pass
        elif self.command is MessageCommand.get_var:
            pass

        return message


class MessageFactory(Factory):
    def __init__(self, msg_type: MessageType, command: MessageCommand, args=None):
        self.content = None
        if msg_type is MessageType.request:
            self.content = RequestFactory(command, args)
        elif msg_type is MessageType.response:
            self.content = ResponseFactory(command, args)
        else:
            raise Exception(f"Incorrect message type: {msg_type.name}. Available types: request or response.")

    def create(self):
        return self.content.create()
