# Author: Taylor Seghesio
# Organization: UNR CSE
# Course: CPE 600
# Most recent date accessed: 30APR2024

# Acknowledgements: (see paper deliverable for formal iEEE listed sources)
# This code was written with the help of the following sources/docs/libraries:
# For assistance with regEx patterns:
# https://blog.netwrix.com/2018/05/29/regular-expressions-for-beginners-how-to-get-started-discovering-sensitive-data/
# https://docs.python.org/3/library/re.html
# For assistance with PyShark:
# https://github.com/KimiNewt/pyshark/
# For assistance with Pandas
# https://pandas.pydata.org/docs/
# For assistance with decoding payload information and unicode
# https://www.geeksforgeeks.org/python-strings-decode-method/
# https://docs.python.org/3/howto/unicode.html
# https://stackoverflow.com/questions/36627895/does-decoding-a-bytestring-using-iso-8859-1-ever-raise-unicodedecodeerror
# For assistance with base64 and decoding authorization header:
# https://docs.python.org/3/library/base64.html
# For assistance/review with/of exception handling
# https://docs.python.org/3/tutorial/errors.html
# Test PCAP Files used to verify program working
# https://github.com/tuftsdev/DefenseAgainstTheDarkArts/blob/gh-pages/labs/lab02-pcaps.md
# IDE Used:
# PyCharm // Python Interpreter: v.3.12


# About code:
# This code is designed to analyze packet capture files to extract personal information that could have leaked into the
# network via free text. It uses regular expressions to find data patterns encapsulated in the PCAP files. These
# expressions are defined for: names, addresses, phone numbers, social security numbers, usernames, passwords, emails,
# and credit card numbers. Some decoding of hex_bytes and base64 strings are required to find the information within the
# HTTP packet/headers in order to read the data and report it to a csv file. This is a valuable tool for network
# security analysis. Specifically this program reads from 6 PCAP files, each pertaining to the capture of data while
# performing experiments on the given operating system (with or without AVG Securities active). This program will output
# 6 csv files in relation to each of the 3 operating systems (if no personal data is found for the pcap, a csv file
# will not be generated). I attempted to create this program in a modular way to leave room for future refactoring.


import pyshark
import re
import pandas as pd
import base64


patterns = {
    'username': re.compile(r'username=[^\&\s]+'),
    'password': re.compile(r'password=[^\&\s]+'),
    'email': re.compile(r'email=[^\&\s]+'),
    'credit_card': re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b'),
    'name': re.compile(r'\b([A-Z][a-z]+ [A-Z][a-z]+)\b'),
    'address': re.compile(r'\d+ \w+ St(?:reet)?'),
    'phone_number': re.compile(r'\b(\d{3}-\d{3}-\d{4})\b'),
    'social_security_number': re.compile(
        r'\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d))([-]?\s?)(?!00)\d\d\3(?!0000)\d{4}\b')
}


def load_traffic(pcap_file):
    with pyshark.FileCapture(pcap_file, display_filter='http') as capture:
        return [packet for packet in capture]


def search_traffic(http_traffic):
    personal_info = []

    for packet in http_traffic:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        info_found = {'Source IP': src_ip, 'Destination IP': dst_ip}

        if hasattr(packet.http, 'file_data'):
            payload = packet.http.file_data.binary_value
            text_data = decode_payload(payload)
            for info_type, pattern in patterns.items():
                matches = pattern.findall(text_data)
                if matches:
                    info_found[info_type] = ', '.join(matches)

        if hasattr(packet.http, 'authorization'):
            auth_data = decode_auth(packet.http.authorization)
            info_found.update(auth_data)

        if len(info_found) > 2:
            personal_info.append(info_found)

    return personal_info


def decode_payload(hex_bytes):
    try:
        text = hex_bytes.decode('utf-8')
    except UnicodeDecodeError:
        text = hex_bytes.decode('ISO-8859-1')
    return text


def decode_auth(value):
    encoded_part = value.split(' ')[1]
    decoded_bytes = base64.b64decode(encoded_part)
    username, password = decoded_bytes.decode('ascii').split(':', 1)
    return {'username': username, 'password': password}


def main():
    pcap_files = {
        'windows11': 'windows11_capture.pcap',
        'macOS': 'macOS_capture.pcap',
        'iOS': 'iOS_capture.pcap',
        'macOS_AVG': 'macOS_AVG_capture.pcap',
        'windows11_AVG': 'windows11_AVG_capture.pcap',
        'iOS_AVG': 'iOS_AVG_capture.pcap',
        'TEST1': 'test1.pcap'
    }

    for os_name, filename in pcap_files.items():
        print(f"Processing {filename}...")
        http_traffic = load_traffic(filename)
        personal_info = search_traffic(http_traffic)

        if personal_info:
            df_personal = pd.DataFrame(personal_info)
            print(f"Data to be written for {os_name}:")
            print(df_personal.head())
            csv_file = f'{os_name}_personal_data.csv'
            df_personal.to_csv(csv_file, index=False)
            print(f"Personal information findings for {os_name} have been saved to '{csv_file}'.")
        else:
            print("No personal information found in pcap.")


if __name__ == '__main__':
    main()
