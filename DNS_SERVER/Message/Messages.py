from Message.Header import *
from Message.Questions import *
from Message.Answers import *


def standart_query(domain_name, type):
    mes = b'\x9b\xce\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    for x in domain_name.split("."):
        mes += len(x).to_bytes(1, "big", signed=False) + x.encode()
    mes += b"\x00"
    mes += type.to_bytes(2, "big", signed=False) + b'\x00\x01'
    return mes


class DNS_MESSAGE:
    def __init__(self):
        self.size = 0
        self.header = DNS_HEADER()


    def unpack(self, byte_str):
        self.size = 0
        self.header = DNS_HEADER()
        self.header.unpack(byte_str)
        self.size += self.header.size
        self.question = DNS_QUESTION(byte_str[self.size:], self.header.QDCOUNT, byte_str)
        self.size += self.question.size
        self.answer = DNS_ANSWER(byte_str[self.size:], self.header.ANCOUNT, byte_str)
        self.size += self.answer.size
        self.authority  = DNS_ANSWER(byte_str[self.size:], self.header.NSCOUNT, byte_str)
        self.size += self.authority.size

        self.additional = DNS_ANSWER(byte_str[self.size:], self.header.ARCOUNT, byte_str)
        self.size += self.additional.size

    def pack_query(self):
        q = self.header.pack()
        q += self.question.pack()
        q += self.answer.pack()
        return q


    def __str__(self):
        return (
f"""Header:
{str(self.header)}
Question:
{str(self.question)}
Answer:
{str(self.answer)}
Authority:
{str(self.authority)}
Additional:
{str(self.additional)}
""")