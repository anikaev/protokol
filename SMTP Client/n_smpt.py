import base64
import json
import socket
from pathlib import Path
import os
import ssl


def request(socket, request):
    socket.send((request + '\n').encode())
    recv_data = ''
    while True:
        data = socket.recv(1024)
        recv_data += data.decode()
        if not data or len(data) < 1024:
            break
    return recv_data

def message_prepare():
    with open(message_filename) as file_msg:

        boundary_msg = "bound.40629"

        headers = f'from: {user_name_from}\n'
        headers += f'to: {get_2list_in_message()}\n'  # пока получатель один
        headers += f'subject: {get_subject_msg()}\n'  # короткая тема на латинице
        headers += 'MIME-Version: 1.0\n'
        headers += 'Content-Type: multipart/mixed;\n' \
                   f'    boundary={boundary_msg}\n'
        # тело сообщения началось
        message_body = f'--{boundary_msg}\n'
        message_body +=  'Content-Transfer-Encoding: base64\n'
        message_body += 'Content-Type: text/plain; charset=utf-8\n\n'
        msg = base64.b64encode(file_msg.read().encode()).decode("UTF-8")
        message_body += msg + '\n'
        # Конец текста письма
        message_body += attach(boundary_msg)
        message = headers + '\n' + message_body + '\n.\n'
        print(message)
        return message

def attach_pattern(content_type):
    def pat_attach(filename, boundary_msg):
        attached_body = f'--{boundary_msg}\n'
        attached_body += 'Content-Disposition: attachment;\n' \
                         f'   filename="{filename}"\n'
        attached_body += 'Content-Transfer-Encoding: base64\n'
        attached_body += f'Content-Type: {content_type};\n\n'

        with open(Path(os.path.join(attach_directory, filename)), 'rb') as picture_file:
            picture = base64.b64encode(picture_file.read()).decode("UTF-8")

        attached_body += picture + '\n'
        return attached_body
    return pat_attach

def attach(boundary_msg):
    attached_body = ''
    files = [z for x, y, z in os.walk(attach_directory)][0]
    switcher = {
        'png': attach_pattern('image/png'),
        'jpg': attach_pattern('image/jpeg'),
        'pdf': attach_pattern('application/pdf'),
        'docx': attach_pattern('application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
    }

    for file in files:
        extend = file.split('.')[1]
        attached_body += switcher[extend](file, boundary_msg)

    attached_body += f'--{boundary_msg}--'
    return attached_body

def rcpt_to():
    for addr in receivers_address:
        print(request(client, f"RCPT TO:{addr}"))

def get_2list_in_message():
    rec_str = ''
    for addr in receivers_address:
        rec_str += f'<{addr}>,\n\t'
    return rec_str[:-3]

def get_subject_msg():
    new_subject = ''
    subject = subject_msg
    while len(subject) > 40:
        new_subject += '=?UTF-8?B?' + base64.b64encode((subject[:40]).encode()).decode() + '?=\r\n\t'
        subject = subject[40:]
    if subject != '':
        new_subject += '=?UTF-8?B?' + base64.b64encode(subject.encode()).decode() + '?='
    return new_subject


config_dir_path = Path(os.path.join(os.path.dirname(__file__)))
config_file = Path(os.path.join(config_dir_path, 'config.json'))

with open(config_file, 'r') as json_file:
    file = json.load(json_file)

    user_name_from = file['FROM']  # считываем из конфига кто отправляет

    receiver_filename = file['REC_FILE']  # считываем из конфига кому отправляем (сделать список)
    with open(Path(config_dir_path, receiver_filename), 'r') as rec_file:
        receivers_address = [line.rstrip() for line in rec_file]

    subject_msg = file['SUBJECT']
    host_addr = file['HOST_ADDR']
    port = file['PORT']
    message_filename = file['MESSAGE_FILE']
    attach_directory = file["ATT_DIR"]

# user_name = 'EmailCluient@yandex.ru'  # ваш логин на яндекс почте - устарело

with open("pswd.txt", "r", encoding="UTF-8") as file:
    password = file.read().strip()  # считываем пароль из файла

ssl_contex = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_contex.check_hostname = False
ssl_contex.verify_mode = ssl.CERT_NONE

with socket.create_connection((host_addr, port)) as sock:
    with ssl_contex.wrap_socket(sock, server_hostname=host_addr) as client:
        print(client.recv(1024).decode('utf-8'))  # в smpt сервер первый говорит
        print(request(client, f'EHLO {user_name_from}'))
        base64login = base64.b64encode(user_name_from.encode()).decode()
        base64password = base64.b64encode(password.encode()).decode()
        print(request(client, 'AUTH LOGIN'))
        print(request(client, base64login))
        print(request(client, base64password))
        print(request(client, f'MAIL FROM:{user_name_from}'))
        rcpt_to()
        print(request(client, 'DATA'))
        print(request(client, message_prepare()))
            # print(request(client, 'QUIT'))




##TODO
##Обработка ошибок Сети
##MIME формат письма: присоединить картинки
##Заголовки письма: Subject, From и т. д.
# сделать конфиг: от кого, список адресов, имя папки с файлами для отправки, имя файла с письмом
# NB тема на русском языке, тема может быть длинная -> разбивается на несколько строк
# MIME типы/подтипы прикрепляемых файлов можно определять по расширениям файлов
