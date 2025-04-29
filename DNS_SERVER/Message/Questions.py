class DNS_QELEMENT:
    def read_lable(self, byte_str, message, lable, readed):
        size_label = byte_str[0]
        byte_str = byte_str[1:]
        if size_label == 0:
            return (lable, readed+1)

        if size_label < 128:
            r_lable = byte_str[:size_label]
            byte_str = byte_str[size_label:]
            return self.read_lable(byte_str, message, lable+'.'+r_lable.decode("utf-8"), readed+size_label+1)

        offset = byte_str[0]
        byte_str = byte_str[1:]
        rootOffset = ((size_label & 0x3F) << 8) | offset
        lable , r =  self.read_lable(message[rootOffset:], message, lable, readed+2)
        return lable, 2



    def __init__(self, byte_str, message):
        self.size = 0
        self.QNAME = ""

        lable, readed = self.read_lable(byte_str, message, "", 0)

        self.size += readed
        byte_str = byte_str[readed:]
        self.QNAME = lable[1:]

        self.QTYPE = byte_str[:2]
        self.QCLASS = byte_str[2:4]
        self.size += 4

    def pack(self):
        q = b""
        for x in self.QNAME.split('.'):
            q += len(x).to_bytes(1, byteorder="big", signed=False)+x.encode()
        q += b'\x00'
        q +=  self.QTYPE + self.QCLASS
        return q

    def __str__(self):
        switcher_class = {
            1 : "Internet",
            2 : "CSNET",
            3 : "CHAOS",
            4 : "HESIOD"
        }
        switcher_type = {
            1: "A",
            2: "NS",
            3: "MD",
            4: "MF",
            5: "CNAME",
            6: "SOA",
            7: "MB",
            8: "MG",
            9: "MR",
            10: "NULL",
            11: "WKS",
            12: "PTR",
            13: "HINFO",
            14: "MINFO",
            15: "MX",
            16: "TXT",
            252: "AXFR",
            253: "MAILB",
            254: "MAILA",
            255: "*"
        }
        return (
f"""QELEMENT
    QNAME: {self.QNAME}
    QTYPE: {switcher_type[int.from_bytes(self.QTYPE, "big", signed=False)]}
    QCLASS: {switcher_class[int.from_bytes(self.QCLASS, "big", signed=False)]}
"""
        )

class DNS_QUESTION:
    def __init__(self, byte_str, count, message):
        self.size = 0
        self.QR = None
        for x in range(count):
            el = DNS_QELEMENT(byte_str, message)
            byte_str = byte_str[el.size:]
            self.size += el.size
            self.QR = el
    def pack(self):
        return self.QR.pack()

    def __str__(self):
        s = str(self.QR)
        return s[:-1]
