import random

import signal
import threading
import pickle
import time
import sys

from DNS_EXCEPTIONS import *
from  Message.Messages import *
from  Message.Header import *
from  Message.Questions import *
from  Message.Answers import *
import socket
import atexit
# Что осталось сделать?

IP_ROOT_DNS_SERVER = '198.41.0.4'
DNS_PORT = 53
def timeout_handler():
    print(DNS_TIME_OUT_EXCEPTION())

class DNS_SERVER:

    def __init__(self):
        try:
            with open("cach.txt", 'rb') as file:
                self.true3_cach = pickle.load(file)
            with open("logs.txt", 'rb') as file:
                t = pickle.load(file)
        except EOFError:
            t = 0
            self.true3_cach = {}
        self.dns_timer  = threading.Timer(1, self.tick_tack)
        self.dns_timer.start()
        cur_t = int(time.time())
        dif_t = cur_t - t
        for x in self.true3_cach.values():
            for rr in x:
                rr.TTL -= dif_t

    def tick_tack(self):
        while True:
            time.sleep(10)
            total_expire = set()
            for x in self.true3_cach.keys():
                expired = set()
                for rr in self.true3_cach[x]:
                    rr.TTL -= 10
                    if rr.TTL < 0:
                        expired.add(rr)

                for expired_rr in expired:
                    self.true3_cach[x].remove(expired_rr)
                if len(self.true3_cach[x]) == 0:
                    total_expire.add(x)
            for t_rr in total_expire:
                del self.true3_cach[t_rr]

    def query_dns_server(self, domain_name, ip_dns_server, type):

        request = standart_query(domain_name, type)
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(request, (ip_dns_server, DNS_PORT))
        try:
            timer = threading.Timer(10.0, timeout_handler)
            timer.start()
            data, server = udp_socket.recvfrom(4096)
        except Exception:
            raise DNS_TIME_OUT_EXCEPTION
        finally:
            timer.cancel()
        udp_socket.close()
        mes = DNS_MESSAGE()
        mes.unpack(data)

        return mes

    def true_resolve(self, domain_name, type):

        dm_name = domain_name
        dns_ip = IP_ROOT_DNS_SERVER

        domain_name = domain_name.split('.')
        domain_name.reverse()

        find_name = ""

        for name in domain_name:
            if (type, dm_name) in self.true3_cach.keys():
                break

            if find_name != "": find_name = name + "." + find_name
            else: find_name = name

            if find_name == "":
                raise DNS_NAME_EXCEPTION

            if (2, find_name) not in self.true3_cach.keys():
                mes = self.query_dns_server(find_name, dns_ip, 2)

                sticky_rr = mes.additional.elements
                for rr in mes.authority.elements:
                    if (2, find_name) not in self.true3_cach.keys():
                        self.true3_cach[(2, find_name)] = [rr]
                    else:
                        self.true3_cach[(2, find_name)].append(rr)

                for rr in sticky_rr:
                    if (rr.TYPE, rr.NAME) not in self.true3_cach.keys():
                        self.true3_cach[(rr.TYPE, rr.NAME)] = [rr]

            try:
                ip_dns_servers = [self.true3_cach[(1, x.RDATA)][0].RDATA for x in self.true3_cach[(2, find_name)]
                                  if (1, x.RDATA) in self.true3_cach.keys()]
            except:
                break
            # Есть липкие записи днс-серверов.
            if len(ip_dns_servers) != 0:
                random_i = random.randint(0, len(ip_dns_servers)-1)
                dns_ip = ip_dns_servers[random_i]
            else:
                # Попробуем найти ip днс-серверов у текущего сервера домена find_name[1:].
                dns_servers = [x.RDATA for x in self.true3_cach[(2, find_name)] if x.TYPE == 2]

                for auth_s in dns_servers:
                    self.true_resolve(auth_s, 1)
                    try:
                        ip_dns_servers.append(self.true3_cach[(1,auth_s)][0].RDATA)
                    except Exception:
                        pass
                try:

                    random_i = random.randint(0, len(ip_dns_servers) - 1)
                    dns_ip = ip_dns_servers[random_i]
                except Exception:
                    pass

        if not (type, dm_name) in self.true3_cach.keys():
            mes = self.query_dns_server(find_name, dns_ip, type)

            ar_rr = mes.authority.elements + mes.additional.elements
            for rr in ar_rr:
                if (rr.TYPE, rr.NAME) not in self.true3_cach.keys():
                    self.true3_cach[(rr.TYPE, rr.NAME)] = [rr]

            for rr in mes.answer.elements:
                if (type, find_name) not in self.true3_cach.keys():
                    self.true3_cach[(type, find_name)] = [rr]
                else:
                    self.true3_cach[(type, find_name)].append(rr)

    # Здесь будет формироваться пакет ответа
    def extract(self, message):
        domain_name = (message.question.QR.QNAME)
        type = int.from_bytes(message.question.QR.QTYPE, "big", signed=False)

        list_rr = self.true3_cach[(type, domain_name)]

        message.header.AA = 1
        message.header.QR = 1
        message.header.RCODE = 0
        byte_s = b""

        for x in list_rr:
            byte_s += x.pack()


        byte_message = message.pack_query()
        byte_message = byte_message[:6] + (len(list_rr)).to_bytes(2, "big" , signed=False)+ byte_message[8:] + byte_s

        res = DNS_MESSAGE()
        res.unpack(byte_message)

        return res.pack_query()


    def resolve(self, message):
        domain_name = (message.question.QR.QNAME)
        type = int.from_bytes(message.question.QR.QTYPE, "big", signed=False)


        if (type, domain_name) in self.true3_cach.keys():
            return self.extract(message)

        self.true_resolve(domain_name, type)

        return self.extract(message)

    def save(self):
        pickle.dump(self.true3_cach, open('cach.txt', 'wb'))
        pickle.dump(int(time.time()), open('logs.txt', 'wb'))


dns_server = DNS_SERVER()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = 'localhost'
port = 53
s.bind((host, port))

try:
    while True:
        try:
            data, address = s.recvfrom(1024)
            mes = DNS_MESSAGE()
            mes.unpack(data)
            try:
                answer = dns_server.resolve(mes)
            except Exception:
                mes.header.RCODE = 2
                answer = mes.pack_query()

            s.sendto(answer, address)
        except (ConnectionResetError, TypeError):
            pass
        dns_server.save()
finally:
    dns_server.save()