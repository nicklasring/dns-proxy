#!/usr/local/bin/python

from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM
from struct import unpack

from dnsfirewall import DNSFirewall

SERVER_ADDRESS = '127.0.0.1'
DNS_PORT = 53
DNS_SERVERS = [
    "9.9.9.9" # Quad9
]

class DNSProxy():
    def __init__(self):
        self._socket = socket(AF_INET, SOCK_DGRAM)
        self._socket.bind((SERVER_ADDRESS, DNS_PORT))

        self._dns_query = None
        self._dns_query_name_length = 0

        self._dns_firewall = DNSFirewall()
        
        print(f'Listening on {SERVER_ADDRESS}:{DNS_PORT}')

    def Relay(self, data):
        try:
            relay_socket = socket(AF_INET, SOCK_DGRAM)
            relay_socket.connect((DNS_SERVERS[0], 53)) # TODO: Use random good DNS Server
            relay_socket.send(data)

        except Exception as E:
            print(E)

    def SetDNSPayload(self, payload):
        self._dns_payload = payload.split(b'\x00',1)

        q_data = unpack('!2H', self._dns_payload[1][0:4])

        self.SetQType(q_data[0])
        self.SetQClass(q_data[1])

    def SetQType(self, qtype):
        self._dns_qtype = qtype

    def SetQClass(self, qclass):
        self._dns_qclass = qclass

    def SetDNSQuery(self, client_data):
        self.SetDNSPayload(client_data[12:])
        self._dns_query = self.GetDNSPayload()[0]

    def GetQType(self):
        return self._dns_qtype

    def GetQClass(self):
        return self._dns_qclass

    def GetDNSPayload(self):
        return self._dns_payload

    def GetDNSQuery(self):
        return self._dns_query

    def GetQname(self):
        b = len(self._dns_query)
        qname_length = b + 1

        qname = unpack(f'!{b}B', self._dns_query[:qname_length])
        length = qname[0]
        qname_raw = ''
        for byte in qname[1:]:
            if (length != 0):
                qname_raw += chr(byte)
                length -= 1
                continue

            length = byte
            qname_raw += '.'

        return qname_raw

    def Start(self):
        while True:
            client_data, client_address = self._socket.recvfrom(1024)
            
            transaction_id = unpack("!H", client_data[:2])[0]
            flags = unpack("!H", client_data[2:4])[0]
            questions = unpack("!H", client_data[4:6])[0]
            answer_rrs = unpack("!H", client_data[6:8])[0]
            authority_rrs = unpack("!H", client_data[8:10])[0]
            additional_rrs = unpack("!H", client_data[10:12])[0]

            self.SetDNSQuery(
                client_data
            )

            qname = self.GetQname()

            if not self._dns_firewall.IsAllowed(qname): 
                print(f'---------\nDomain: {qname} is not allowed\n---------')
                pass

            qtype =  self.GetQType()
            qclass = self.GetQClass()
            
            print(
                f'Transaction ID: {transaction_id}\nFlags: {flags}\nQuestions: {questions}\nAnswer RRS: {answer_rrs}\nAuthority RRS {authority_rrs}\nAdditional RRS {additional_rrs}\nQuery Name: {qname}\nQuery Type: {qtype}\nQuery Class: {qclass}'''
            )

            print('Trying to send ...')
            self.Relay(client_data)

if __name__ == '__main__':
    DNSProxy().Start()