import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Lookup details on fernet in the cryptography.io documentation    
def encrypt_with_aes(input_string, password, salt):
    # generate key suitable for Fernet
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8')) # call the Fernet encrypt method
    return encrypted_data    

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data) # call the Fernet decrypt method
    return decrypted_data.decode('utf-8')

salt = b"Tandon" # Remember it should be a byte-object
password = "your_nyu_email@nyu.edu"  # REPLACE with your Gradescope-registered NYU email
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt) # exfil function
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # exfil function

# For future use    
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# A dictionary containing DNS records mapping hostnames to different types of DNS data.
# Keys are FQDNs (note trailing dot)
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],  # List of (preference, mail server) tuples
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.', # mname
            'admin.example.com.', # rname
            2023081401, # serial
            3600, # refresh
            1800, # retry
            604800, # expire
            86400, # minimum
        ),
    },

    # Assignment-specified A records:
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102'
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103'
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104'
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105'
    },
    # nyu.edu with additional records (TXT will contain encrypted payload string)
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        # Fernet already returns base64-safe bytes -> decode to str for TXT
        dns.rdatatype.TXT: (encrypted_value.decode('utf-8'),),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.'
    },
}

def run_dns_server():
    # Create a UDP socket and bind it to the local IP address and port
    # Using 127.0.0.1 and port 8053 for local testing (non-root). Change to ('0.0.0.0', 53) if running with privileges.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 8053))

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(4096)
            # Parse the request using the `dns.message.from_wire` method
            request = dns.message.from_wire(data)
            # Create a response message using the `dns.message.make_response` method
            response = dns.message.make_response(request)

            # Get the question from the request
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if there is a record in the `dns_records` dictionary that matches the question
            if qname in dns_records and qtype in dns_records[qname]:
                # Retrieve the data for the record and create an appropriate `rdata` object for it
                answer_data = dns_records[qname][qtype]

                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    # answer_data is a list of (preference, server)
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    #
