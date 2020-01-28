import telebot
import socket
import dns.resolver
from dns import resolver,reversename
from datetime import datetime as dt
import time
import sys

bot = telebot.TeleBot('1040254461:AAGwZzI-wsuqRyP2FlvQ31fSNEGB39nRGBo')
@bot.message_handler(commands=['start'])
def start_message(message):
    bot.send_message(message.chat.id, 'Вітаємо! WhoisHelperBot допоможе вам із DNS та WHOIS запитами! Введіть /help для отримання довідки.')
@bot.message_handler(content_types=['text'])

def start(message):
    if message.text == '/help':
        bot.send_message(message.from_user.id, "Список команд:\n /start - розпочати;\n /help - список команд;\n /nslookup  - отримати А- запис домену;\n /ptr - отримати PTR- запис IP-адреси;\n /whois - отримати WHOIS реквізити;\n /spf - переглянути SPF запис домену;\n /cancel - скасувати виконання запиту.");
    if message.text == '/nslookup':
        bot.send_message(message.from_user.id, "Введіть доменне ім'я.");
        bot.register_next_step_handler(message, get_nslookup); 
    if message.text == '/ptr':
        bot.send_message(message.from_user.id, "Введіть IP-адресу.");
        bot.register_next_step_handler(message, get_ptr);
    if message.text == '/whois':
         bot.send_message(message.from_user.id, "Введіть IP-адресу чи доменне ім'я.");
         bot.register_next_step_handler(message, get_whois); 
    if message.text == '/spf':
         bot.send_message(message.from_user.id, "Введіть доменне ім'я.");
         bot.register_next_step_handler(message, get_txt);
    if message.text == '/canel':
         bot.register_next_step_handler(message, start);
    if message.text != '/cancel' and message.text != '/spf' and message.text != '/whois' and message.text != '/ptr' and message.text != '/nslookup' and message.text != '/help' and message.text != '/start':
         bot.send_message(message.from_user.id, "Команду введено невірно. Щоб отримати список команд, введіть /help");


def get_nslookup(message):
    domain = message.text;
    if domain == '/cancel':
        return;
    my_resolver = dns.resolver.Resolver();
    my_resolver.nameservers = ['8.8.8.8'];
    ip_adresses = 'А- запис було визначено за допомогою Google Public DNS (8.8.8.8):\n';
    enter = '\n';
    try:
        answer_IP = my_resolver.query(domain, 'A');
        for ans in answer_IP:
            ip_adresses += str(ans) + enter;      
        bot.send_message(message.from_user.id, ip_adresses);
    except Exception:
             bot.send_message(message.from_user.id, 'Сталася помилка. Спробуйте ще раз.');

def get_ptr(message):
    ipadr = message.text;
    if ipadr == '/cancel':
        return;
    answ = 'PTR- запис було визначено за допомогою Google Public DNS (8.8.8.8):\n';
    answer_domains = '';
    my_resolver = dns.resolver.Resolver();
    my_resolver.nameservers = ['8.8.8.8'];
    try: 
        addr= reversename.from_address(ipadr);
        answer_domain = my_resolver.query(addr,"PTR");
        for domain in answer_domain:
            answer_domains += str(domain) + '\n';
        bot.send_message(message.from_user.id, answ + answer_domains);
    except Exception:
             bot.send_message(message.from_user.id, 'Сталася помилка. Спробуйте ще раз.');

def get_txt(message):
    txt = message.text;
    if txt == '/cancel':
        return;
    try:
        txtresolv = dns.resolver.query(txt);
    except dns.exception.DNSException as e:
        if isinstance(e, dns.resolver.NXDOMAIN):
            bot.send_message(message.from_user.id, "Такого домену не існує: %s" % txt);
            return;
        elif isinstance(e, dns.resolver.Timeout):
            bot.send_message(message.from_user.id, "Timed out while resolving %s" % txt);
            return;
        else:
            bot.send_message(message.from_user.id, "Сталася помилка. Спробуйте ще раз.");
            return;
    txtrecord = b'TXT record:\n';
    enter = b'\n';
    try: 
        answers = dns.resolver.query(txt, 'TXT');
        for rdata in answers:
            for txt_string in rdata.strings:
                txtrecord += txt_string + enter;
        bot.send_message(message.from_user.id, txtrecord);
        mxtoolboxlink = 'https://mxtoolbox.com/SuperTool.aspx?action=spf%3a' + txt + '&run=toolpage';
        bot.send_message(message.from_user.id, 'Детальна інформація доступна за посиланням: \n' + mxtoolboxlink);
    except Exception:
        bot.send_message(message.from_user.id, 'TXT запис порожній.');      
 

def whois(ip):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.arin.net", 43))
    s.send(('n ' + ip + '\r\n').encode())

    response = b""
    # setting time limit in secondsmd
    startTime = time.mktime(dt.now().timetuple())
    timeLimit = 3
    while True:
        elapsedTime = time.mktime(dt.now().timetuple()) - startTime
        data = s.recv(4096)
        response += data
        if (not data) or (elapsedTime >= timeLimit):
            break
    s.close()
    global resp;
    resp = response.decode();  
 
 
def whois_ripe(ip):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.ripe.net", 43))
    s.send(('-B -r --sources RIPE ' + ip + '\r\n').encode())

    response = b""
    # setting time limit in secondsmd
    startTime = time.mktime(dt.now().timetuple())
    timeLimit = 3
    flag = 1;
    while True:
        elapsedTime = time.mktime(dt.now().timetuple()) - startTime
        data = s.recv(4096)
        response += data
        flag += 1
        if (not data) or (elapsedTime >= timeLimit):
            break
    s.close()
    global resp_ripe;
    resp_ripe = response.decode();

def whois_apnic(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.apnic.net", 43))
    s.send(('-d ' + ip + '\r\n').encode())

    response = b""
    # setting time limit in secondsmd
    startTime = time.mktime(dt.now().timetuple())
    timeLimit = 3
    while True:
        elapsedTime = time.mktime(dt.now().timetuple()) - startTime
        data = s.recv(4096)
        response += data
        if (not data) or (elapsedTime >= timeLimit):
            break
    s.close()
    global resp_apnic;
    resp_apnic = response.decode(); 
    
def whois_afrinic(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.afrinic.net", 43))
    s.send(('-B -d ' + ip + '\r\n').encode())
    response = b""
    # setting time limit in secondsmd
    startTime = time.mktime(dt.now().timetuple())
    timeLimit = 3
    while True:
        elapsedTime = time.mktime(dt.now().timetuple()) - startTime
        data = s.recv(4096)
        response += data
        if (not data) or (elapsedTime >= timeLimit):
            break
    s.close()
    global resp_afrinic;
    resp_afrinic = response.decode();

def whois_lacnic(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.lacnic.net", 43))
    s.send((ip + '\r\n').encode())
    response = b""
    # setting time limit in secondsmd
    startTime = time.mktime(dt.now().timetuple())
    timeLimit = 3
    while True:
        elapsedTime = time.mktime(dt.now().timetuple()) - startTime
        data = s.recv(4096)
        response += data
        if (not data) or (elapsedTime >= timeLimit):
            break
    s.close()
    global resp_lacnic;
    resp_lacnic = response.decode();
    
def get_whois(message): 
    domain = message.text;
    if domain == '/cancel':
        return;
    try:
        ip = socket.gethostbyname(domain);
    except Exception:
        bot.send_message(message.from_user.id, 'Сталася помилка. Спробуйте ще раз.');
        return;
    whois(ip);
    if resp.find('whois.ripe.net',0,len(resp))!=-1:
        whois_ripe(ip)
        bot.send_message(message.from_user.id, resp_ripe); 
    elif resp.find('whois.apnic.net',0,len(resp))!=-1:
        whois_apnic(ip)
        bot.send_message(message.from_user.id, resp_apnic);
    elif resp.find('whois.afrinic.net',0,len(resp))!=-1:
        whois_afrinic(ip);
        bot.send_message(message.from_user.id, resp_afrinic);
    elif resp.find('whois.lacnic.net',0,len(resp))!=-1:
        whois_lacnic(ip);
        bot.send_message(message.from_user.id, resp_lacnic);
    else:
        bot.send_message(message.from_user.id, resp);
 
bot.polling()