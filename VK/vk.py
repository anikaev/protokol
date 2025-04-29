import json
import urllib
from urllib.request import urlopen
from urllib import error
from urllib.error import URLError, HTTPError

with open('token.txt') as f:
    token = f.read()

def get_content(name):
    try:
        resp = urlopen(name, data=None, timeout=10)
    except urllib.error.URLError as e:
        return None
    else:
        return resp

def get_count_chat():
    data = json.load(
        get_content(
            f"https://api.vk.com/method/account.getCounters?&access_token={token}&v=5.131"
        )
    )
    return data["response"]['messages']

def get_profile_info():
    data = json.load(
        get_content(
            f"https://api.vk.com/method/account.getProfileInfo?&access_token={token}&v=5.131"
        )
    )
    response = data['response']
    sex_switcher = {
        1 : "Женский",
        2 : "Мужской"
    }
    return {
        'first_name': response['first_name'],
        'last_name': response['last_name'],
        'home_town': response['home_town'],
        'bdate': response['bdate'],
        'sex': sex_switcher[response['sex']],
        'screen_name': response['screen_name']
    }

def get_country():
    data = json.load(
        get_content(
            f"https://api.vk.com/method/account.getInfo?&access_token={token}&v=5.131"
        )
    )
    return data['response']['country']


profile_info = get_profile_info()

print(f"""
Пользователь: {profile_info['first_name']} {profile_info["last_name"]}
Пол: {profile_info['sex']}
Родной город: {profile_info['home_town']}
Страна: {get_country()}
Псевдоним: {profile_info['screen_name']}
Дата рождения: {profile_info['bdate']}
Количество непрочитанных чатов: {get_count_chat()}
""")