#!/usr/bin/env python3

import yaml
import ssl
import socket
import time
import sys

# https://docs.python.org/3/library/ssl.html
def check_host(hostname):
    try:
        print("checking " + hostname)
        port = 443
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

    except ssl.SSLCertVerificationError as e:
        print("  error:" + str(e.verify_code) + ":" + e.verify_message)

if (len(sys.argv) == 1):
    print("usage: check.py config.yaml")
config = yaml.safe_load(open(sys.argv[1]))
for host in config['hosts']:
    check_host(host)

