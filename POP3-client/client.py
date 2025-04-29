import base64
import json
import socket
from pathlib import Path
import os
import ssl
import re

def parse_headers(headers_lines):
    headers_list = []
    header = ''

    for line in headers_lines:
        if line.startswith('\t') or line.startswith('    '):
            header += line
        else:
            if header != '':
                if not header.endswith('\n'):
                    header += '\n'
                headers_list.append(header+'\n')
            header = line+'\n'
    if header != '':
        headers_list.append(header+'\n')
    return headers_list

def request(socket, request):
    socket.send((request + '\n').encode())
    recv_data = ''
    while True:
        data = socket.recv(1024)
        recv_data += data.decode()
        if not data or len(data) < 1024:
            break
    return recv_data

def read_multyline(client):
    ans = ''
    while '\r\n.\r\n' not in ans:
        data = client.recv(1024).decode('utf-8')
        ans += data
    return ans

def load_letter(number):
    client.send(("RETR "+str(number) + '\n').encode())
    letter = read_multyline(client)
    letter_file.write(letter.replace('\r\n', '\n'))


with open("pswd.txt", "r", encoding="UTF-8") as file:
    PASSWORD = file.read().strip()

LOGIN = "AllureAsura"
HOST_ADDR = 'pop.yandex.ru'
PORT = "995"

COUNT_TOP_LINE = 10


ssl_contex = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_contex.check_hostname = False
ssl_contex.verify_mode = ssl.CERT_NONE

headers_file = open('headers.txt', 'w')
letter_file = open('letter.txt', 'w')
top_file = open('top.txt', 'w')
log = open('log.txt', 'w')


with socket.create_connection((HOST_ADDR, PORT)) as sock:
    with ssl_contex.wrap_socket(sock, server_hostname=HOST_ADDR) as client:
        log.write(client.recv(1024).decode('utf-8')+'\n')  # в pop3 сервер первый говорит
        # Авторизация
        log.write(request(client, f"USER {LOGIN}"+'\n'))
        log.write(request(client, f"PASS {PASSWORD}"+'\n'))
        # количество писем в mailbox
        stat = request(client, "STAT")
        count_letters = stat.split(' ')[1]
        log.write(stat+'\n')

        if count_letters != 0:
            # Скачать письмо с вложением
            load_letter(1)
            # Скачиваем заголовки письма и "топ"
            log.write(request(client, "TOP 1 10")+'\n')
            top = read_multyline(client)
            log.write(top+'\n')
            # Сначала заголовки, перевод строки, тело сообщения
            headers = parse_headers(top.split('\r\n\r\n')[0].split('\r\n'))

            content_type = None
            enc = None
            # Записываем заголовки и Вычленяем Content-Type
            for header in headers:
                headers_file.write(header)

            body_message = "\r\n\r\n".join(top.split('\r\n\r\n')[1:])

            i = 0

            for line in body_message.split('\r\n'):
                if i > COUNT_TOP_LINE:
                    break
                top_file.write(line+'\n')
                i += 1

        else:
            print("No one letter in mailbox")
        print(request(client, "QUIT"))


headers_file.close()
letter_file.close()
top_file.close()
log.close()