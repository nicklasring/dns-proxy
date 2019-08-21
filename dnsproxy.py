#!/usr/local/bin/python

from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM, SHUT_WR
from struct import unpack, pack

from dnsfirewall import DNSFirewall

SERVER_ADDRESS = '127.0.0.1'
DNS_PORT = 53
DNS_SERVERS = [
    "1.1.1.1" # Quad9
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
            response = relay_socket.recv(4096)
            self._socket.sendto(response, self._client_address)
            relay_socket.shutdown(SHUT_WR)
        except Exception as E:
            print(E)

    def RelayFake(self, data):
        # TODO: Why does this work, its a query not a response ?
        request_header = data[:(12+self.GetQnameLength()+4)]
        answer_localhost = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x03\x84\x00\x04\x7f\x00\x00\x01\x00\x00\x29\x05\xac\x00\x00\x00\x00\x00\x00'
        request_header += answer_localhost

        try:
            self._socket.sendto(request_header, self._client_address)
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

    def SetQnameLength(self, length):
        self._qname_length = length

    def GetQType(self):
        return self._dns_qtype

    def GetQClass(self):
        return self._dns_qclass

    def GetDNSPayload(self):
        return self._dns_payload

    def GetDNSQuery(self):
        return self._dns_query

    def GetQnameLength(self):
        return self._qname_length

    def GetQname(self):
        b = len(self._dns_query)
        qname_length = b + 1

        self.SetQnameLength(qname_length)

        qname = unpack(f'!{b}B', self._dns_query[:self.GetQnameLength()])
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
            client_data, self._client_address = self._socket.recvfrom(1024)

            self.SetDNSQuery(
                client_data
            )

            if not self._dns_firewall.IsAllowed(self.GetQname()): 
                print(f'Responding with fake DNS for: {self.GetQname()}...')
                self.RelayFake(client_data)
                continue
            else:
                print(f'Relaying DNS Query for: {self.GetQname()}...')
                self.Relay(client_data)

if __name__ == '__main__':
    DNSProxy().Start()