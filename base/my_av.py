#!/usr/bin/python3

import re
try:
    from difflib import SequenceMatcher
except Exception as e:
    pass

def parse_url(url):
    path, query, fragment = '', '', ''
    if "://" in url:
        protocol, url = url.split("://")

    # geth the host
    host = url.split("/")[0]

    # get the fragment if existent
    if '#' in url:
        fragment = url.split("#")[1]

    # get the query if existent
    if '?' in url:
        query = url.split("?")[1].replace(f'#{fragment}', '')

    path = url.replace(host, '').replace(f'?{query}', '')

    return host, path, query, fragment


def is_malicious(host, path):
    # this function checks if the url contains any signs of malware

    # check for common file extensions
    if '.' in path:
        extensions = ['exe', 'bin', 'sh', 'pl']
        extension = path.split('.')[-1]
        if extension in extensions:
            return 1

    main_domain = host.split('.')[-2]
    # if known goood hosts, not malicious
    if main_domain in whitelist:
        return 0

    # if hostname is too similar but not the same with a whitelisted domain,
    # probbly malicious
    for good_host in whitelist:
        ratio = 0
        try:
            ratio = SequenceMatcher(None, good_host, main_domain).ratio()
        except Exception:
            pass
        if ratio > 0.7:
            return 1
        # also if whitelisted domain is included in hostname
        if good_host in main_domain and main_domain != good_host:
            return 1

    # if hostname is too long, may be malicious
    if len(host) > 31:
        return 1

    # if too many numbers may be a malicious ip
    no_numbers = 0
    for char in charset:
        if char in host:
            no_numbers += 1
    if no_numbers >= 0.1 * len(host):
        return 1

    # if connecting to a specific port or credentials, maybe malicious
    if ':' in host or '@' in host:
        return 1

    # if double com extension may be a junk url ,so malicious
    host = host + '/'
    if len(re.findall(r"([^\w]+)com([^\w]+|/)", host)) > 1:
        return 1
    host = host[:-1]

    # check for bad chars
    if '~' in path and '.htm' not in path:
        return 1

    if 'secur' in path or 'paypal' in path or 'wp-admin' in path:
        return 1

    return 0


# some useful data
charset = "1234567890"
whitelist = ['google', 'facebook', 'googlegroups', 'paypal', 'twitter', 'bing',
             '123people', 'whatsapp', 'bdnews24']

# load the list of known malicious hosts and strip newlines
with open("../data/url_dataset/domains_database", 'r') as f:
    malicious_domains = f.readlines()
    malicious_domains = [i.rstrip() for i in malicious_domains]

# now read the list of urls to analyze
urls_file = open("../data/url_dataset/urls.in", 'r')
predictions_file = open("urls-predictions.out", 'w')

# for each url, analyze
url = urls_file.readline().rstrip()
while url != '' and url:
    malicious = 0
    host, path, query, fragment = parse_url(url)

    # if host is known to be malicious, flag it
    for mal_domain in malicious_domains:
        if mal_domain in host:
            malicious = 1

    if is_malicious(host, path):
        malicious = 1

    # now output into the file
    predictions_file.write(f"{malicious}\n")

    # read each line and parse it
    url = urls_file.readline().rstrip()

urls_file.close()
predictions_file.close()

# HERE STARTS TASK 2

try:
    import time
    from datetime import timedelta
except Exception as e:
    pass

# some macros for field numbers
flow_duration = 4
flow_payload_avg = 16
src_ip_field = 0
dst_ip_field = 2

# cryptominers seem to have this info
cryptominer_payload_avg = 40.0

# this is the list with evil ips
evil_ips = ['']


def parse_time(duration):
    days, duration = duration.split(' days ')
    days = int(days) * 86400
    try:
        t_struct = time.strptime(duration, '%H:%M:%S.%f')
        seconds = timedelta(hours=t_struct.tm_hour, minutes=t_struct.tm_min,
                            seconds=t_struct.tm_sec).total_seconds()
        miliseconds = 0
        if '.' in duration:
            miliseconds = float(f"0.{duration.split('.')[1]}")
    except Exception as e:
        return 0
    # return total number of seconds
    return float(days) + seconds + miliseconds


def parse_traffic(packet):
    # get the fields we need for analyzing
    duration = packet.split(',')[flow_duration]
    payload_avg = packet.split(',')[flow_payload_avg]
    src_ip = packet.split(',')[src_ip_field]
    dst_ip = packet.split(',')[dst_ip_field]

    return parse_time(duration), float(payload_avg), src_ip, dst_ip


def is_malicious_traffic(packet):
    duration, payload_avg, src_ip, dst_ip = parse_traffic(packet)

    # if payload is 0, not malicious
    if payload_avg == 0.0:
        return 0

    # if broadcast, not malicious
    if '255.255.255.255' in dst_ip:
        return 0

    # check if IP is known to be bad
    if src_ip in evil_ips:
        return 1

    # if duration is bigger than one second, probably malicious
    if duration > 1.0:
        evil_ips.append(src_ip)
        return 1

    if payload_avg == cryptominer_payload_avg:
        evil_ips.append(src_ip)
        return 1

    return 0


# now read the list of traffic packets to analyze
traffic_file = open("../data/network_dataset/traffic.in", 'r')
predictions_file = open("traffic-predictions.out", 'w')

# first line is junk
packet = traffic_file.readline()
packet = traffic_file.readline().rstrip()

while packet != '' and packet:
    malicious = 0

    if is_malicious_traffic(packet):
        malicious = 1

    # now output into the file
    predictions_file.write(f"{malicious}\n")

    # read each line and parse it
    packet = traffic_file.readline().rstrip()

traffic_file.close()
predictions_file.close()
