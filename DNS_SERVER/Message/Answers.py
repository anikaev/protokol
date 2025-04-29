
class DNS_RES_RECORD:
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
        lable, r = self.read_lable(message[rootOffset:], message, lable, readed+2)
        return lable, 2

    def deparse_RDATA(self):
        q = b""
        if self.TYPE == 2:
            length_RDATA = 0
            for x in self.RDATA.split("."):
                q += len(x).to_bytes(1, byteorder="big", signed=False) + x.encode()
                length_RDATA += 1 + len(x)
            q += b'\x00'
            return length_RDATA+1, q
        if self.TYPE == 1:
            for x in self.RDATA.split('.'):
                q += int(x).to_bytes(1, "big", signed=False)
            return 4, q

        if self.TYPE == 6:
            return self.RDLENGTH, self.RDATA

    def parse_RDATA(self, message):
        if self.TYPE == 2:
            lable, readed = self.read_lable(self.RDATA, message, "", 0)
            self.RDATA = lable[1:]
        if self.TYPE == 1:
            self.RDATA =(
                str(self.RDATA[0]) + "." +
                str(self.RDATA[1]) + "." +
                str(self.RDATA[2]) + "." +
                str(self.RDATA[3])
            )
        if self.TYPE == 28:
            self.RDATA = (
                    hex(self.RDATA[0])[2:].upper() + ":" +
                    hex(self.RDATA[1])[2:].upper() + ":" +
                    hex(self.RDATA[2])[2:].upper() + ":" +
                    hex(self.RDATA[3])[2:].upper() + ":" +
                    hex(self.RDATA[4])[2:].upper() + ":" +
                    hex(self.RDATA[5])[2:].upper() + ":" +
                    hex(self.RDATA[6])[2:].upper() + ":" +
                    hex(self.RDATA[7])[2:].upper()
            )

    def __init__(self, byte_str, message):
        self.size = 0
        self.NAME = ""
        lable, readed = self.read_lable(byte_str, message, "", 0)
        self.NAME = lable[1:]
        self.size += readed
        byte_str = byte_str[readed:]
        self.TYPE = int.from_bytes(byte_str[:2], "big", signed=False)
        self.size += 2
        byte_str = byte_str[2:]
        self.CLASS = byte_str[:2]
        self.size += 2
        byte_str = byte_str[2:]

        self.TTL = int.from_bytes(byte_str[:4], "big", signed=False)
        self.size += 4
        byte_str = byte_str[4:]

        self.RDLENGTH = int.from_bytes(byte_str[:2], "big", signed=False)
        self.size += 2
        byte_str = byte_str[2:]
        self.RDATA = byte_str[:self.RDLENGTH]
        self.size += self.RDLENGTH

        self.parse_RDATA(message)


    def pack(self):
        a = b""
        for x in self.NAME.split('.'):
            a += len(x).to_bytes(1, byteorder="big", signed=False) + x.encode()
        a += b'\x00'
        a += self.TYPE.to_bytes(2, byteorder="big", signed=False)
        a += self.CLASS
        a += self.TTL.to_bytes(4, "big", signed=False)

        length_RDATA, RDATA =  self.deparse_RDATA()
        a += length_RDATA.to_bytes(2, "big", signed=False)
        a += RDATA

        return a

    def __str__(self):
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
            28: "AAAA",
            33: "SRV",

        }
        switcher_class = {
            1 : "Internet",
            2 : "CSNET",
            3 : "CHAOS",
            4 : "HESIOD"
        }
        try:
            t = switcher_type[self.TYPE]
        except KeyError:
            t = -1

        return (
f"""
NAME: {self.NAME}
Type: {t}
Class: {switcher_class[int.from_bytes(self.CLASS, "big", signed=False)]}
TTL: {self.TTL}
RDLENGTH: {self.RDLENGTH}
RDATA: {self.RDATA}
""")

class DNS_ANSWER:
    def __init__(self, byte_str, count, message):
        self.size = 0
        self.elements = []
        for x in range(count):
            rr = DNS_RES_RECORD(byte_str, message)
            self.size += rr.size
            byte_str = byte_str[rr.size:]
            self.elements.append(rr)
    def pack(self):
        ans = b""
        for a in self.elements:
            ans += a.pack()
        return ans

    def __str__(self):
        s = ""
        for x in self.elements:
            s += str(x) +"\n"
        return s[:-1]
