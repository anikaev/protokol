import random


class DNS_HEADER:
    def __init__(self):
        self.size = 0
        self.ID = random.randint(3,30000)
        self.QR = -1
        self.OPCODE = -1
        pass

    def pack(self):
        q = self.ID.to_bytes(2, byteorder="big", signed=False)
        q += (self.QR << 7 | (self.OPCODE << 3) | (self.AA << 2) |
        (self.TC << 1) | self.RD).to_bytes(1, "big", signed=False)
        q += ((self.RA << 7) | (self.Z << 6) | self.RCODE).to_bytes(1, "big",signed=False)
        q += self.QDCOUNT.to_bytes(2, "big", signed=False)
        q += self.ANCOUNT.to_bytes(2, "big", signed=False)
        q += self.NSCOUNT.to_bytes(2, "big", signed=False)
        q += self.ARCOUNT.to_bytes(2, "big", signed=False)
        return q


    def unpack(self, byte_str):
        self.size = 12
        self.ID = int.from_bytes(byte_str[:2], "big", signed=False)
        self.QR = byte_str[2] >> 7
        self.OPCODE = (byte_str[2] & 0x78) >> 3
        self.AA = (byte_str[2] & 0x07) >> 2
        self.TC = (byte_str[2] & 0x03) >> 1
        self.RD = byte_str[2] & 0x01
        self.RA = (byte_str[3] & 0x80) >> 7
        self.Z = (byte_str[3] & 0xd0) >> 5
        self.RCODE = byte_str[3] & 0x0F
        self.QDCOUNT = int.from_bytes(byte_str[4:6], "big", signed=False)
        self.ANCOUNT = int.from_bytes(byte_str[6:8], "big", signed=False)
        self.NSCOUNT = int.from_bytes(byte_str[8:10], "big", signed=False)
        self.ARCOUNT = int.from_bytes(byte_str[10:12], "big", signed=False)

    def __str__(self):
        return (
f"""    ID: {self.ID}
    QR: {self.QR}
    OPCODE: {self.OPCODE}
    AA: {self.AA}
    TC: {self.TC}
    RD: {self.RCODE}
    RA: {self.RA}
    RCODE: {self.RCODE}
    QDCOUNT: {self.QDCOUNT}
    ANCOUNT: {self.ANCOUNT}
    NSCOUNT: {self.NSCOUNT}
    ARCOUNT: {self.ARCOUNT}
""")
