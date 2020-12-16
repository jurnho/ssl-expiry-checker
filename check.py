#!/usr/bin/env python3

import yaml
import ssl
import socket
import time
import sys
import smtplib
from email.message import EmailMessage

# parse string of "hostname" or "hostname:port"
def parse_host_port(hostname_and_optional_port):
    if ":" in hostname_and_optional_port:
        return hostname_and_optional_port.split(":", 1)
    return [hostname_and_optional_port, 443]

# https://docs.python.org/3/library/ssl.html
def check_host(hostname_and_optional_port):
    try:
        [hostname, port] = parse_host_port(hostname_and_optional_port)
        print("checking " + hostname + ", port " + str(port))
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate_info = ssock.getpeercert()
                # print(certificate_info)
                not_after_timestamp = ssl.cert_time_to_seconds(certificate_info['notAfter'])
                print('  not_after_timestamp: ' + str(not_after_timestamp))
                now = time.time()
                seconds_til_expiry = not_after_timestamp - now
                minutes_til_expiry = seconds_til_expiry / 60
                hours_til_expiry = minutes_til_expiry / 60
                days_until_expiry = hours_til_expiry / 24
                print ('  expires in ' + str(int(days_until_expiry)) + ' days')
                return {
                    "hostname": hostname,
                    "port": port,
                    "expired": False,
                    "days_until_expiry": days_until_expiry
                }

    except ssl.SSLCertVerificationError as e:
        # https://github.com/openssl/openssl/blob/master/include/openssl/x509_vfy.h.in
        print("  error:" + str(e.verify_code) + ":" + e.verify_message)
        if e.verify_code == 10:
            return {
                "hostname": hostname,
                "port": port,
                "expired": True
            }
        # return expired anyway...
        return {
                            "hostname": hostname,
                            "port": port,
                            "expired": True
                        }



def send_alert_smtp(result, smtp_config):
    server = smtplib.SMTP_SSL(smtp_config['host'])

    server.login(smtp_config['username'],      smtp_config['password'])
    msg = EmailMessage()
    msg['From'] = smtp_config['from_address']
    msg['To'] = smtp_config['to_address']
    msg['Subject'] = 'ssl-expiry-checker ' + result['hostname']

    content = "ssl-expiry-checker"
    content = content + "\nhost: " + result['hostname'] + ":" + str(result['port'])
    if 'days_until_expiry' in result:
        content = content + "\ncertificate: " + str(int(result['days_until_expiry'])) + " days until expiry"
    if result['expired']:
        content = content + "\ncertificate: expired"

    msg.set_content(content)

    server.send_message(msg)

    server.quit()


def send_alert(result, alert_config):
    if (alert_config['smtp']):
        send_alert_smtp(result, alert_config['smtp'])


def should_send_alert(result):
    if (result["expired"]):
        return True
    if result["days_until_expiry"] <= config['alert']['minimum_days_until_expiry']:
        return True
    return False

def execute(config):
    results = list(map(check_host, config['hosts']))

    for result in results:
        if (should_send_alert(result)):
            send_alert(result, config['alert'])

def execution_and_repeat(config):
    while True:
        execute(config)
        if 'repeat_interval_seconds' not in config:
            print ('done')
            return
        # wait
        sleep_time_seconds = int(config['repeat_interval_seconds'])
        time.sleep(sleep_time_seconds)

if (len(sys.argv) == 1):
    print("usage: check.py config.yaml")
config = yaml.safe_load(open(sys.argv[1]))
execution_and_repeat(config)