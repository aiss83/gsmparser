#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 Alexander I. Shaykhrazeev
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Used to analyse ISSGPRS data records with 3GPP parser
"""
from subprocess import Popen, PIPE
import argparse
import string
import sys
import os


class GSMMessageParser(object):
    # Available GSM protocols to parse
    gsm_protocols = {
        'RR':           'gsm_a_ccch',
        'RLC_Uplink':   'gsm_rlcmac_ul',
        'RLC_Downlink': 'gsm_rlcmac_dl',
        'LLC':          'llc',
        'GPRS_LLC':     'gprs_llc',
        'SNDCP':        'sndcp',
        'SNDCP_XID':    'sndcpxid'
    }

    def writeTempPcap(self, message):
        try:
            with open('msg_text.txt', 'w') as msgFile:
                msgFile.write('0000 ' + message)
        except IOError as err:
            sys.stderr.write(err.message)
            return False

        return True

    def call_text2pcap(self, message):

        if self.writeTempPcap(message):
            p = Popen('text2pcap -q -l 147 msg_text.txt pcap_temp.pcap', shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            p.wait()
            (out, err) = p.communicate()
            if p.returncode:
                print(err)
                return False
        else:
            return False

        os.unlink('msg_text.txt')

        return True

    def call_tshark(self, protocol):
        cmd = 'tshark -r pcap_temp.pcap -Ttext -V -o "uat:user_dlts:\\\"User 0 (DLT=147)\\\",' \
              '\\\"%s\\\",\\\"0\\\",\\\"\\\",\\\"0\\\",\\\"\\\""' % self.gsm_protocols[protocol]
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        p.wait()
        (out, err) = p.communicate()
        result = []
        if p.returncode:
            print(err)
            return False
        else:
            result = out.decode('utf-8', 'strict').splitlines()
            os.unlink('pcap_temp.pcap')

        return True, result

    def checkCorrect(self, message, protocol):
        if protocol not in self.gsm_protocols.keys():
            return False

        msg = message.replace(' ', '')
        onlyHex = all(c in string.hexdigits for c in msg)
        pow2 = (len(msg) % 2 == 0)
        if onlyHex and pow2:
            return True

        return False

    def parse(self, arguments):
        res = False
        text = []
        if self.checkCorrect(arguments.message, arguments.protocol):
            if self.call_text2pcap(message=arguments.message):
                res, text = self.call_tshark(protocol=arguments.protocol)

        if res:
            return text
        else:
            return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process messages of 3GPP')
    parser.add_argument('protocol', metavar='Proto', type=str, help='Protocol of specified 3GPP message')
    parser.add_argument('message', metavar='Msg', type=str, help='Hexadecimal string of message octets')
    args = parser.parse_args()
    result = GSMMessageParser().parse(arguments=args)
    for line in result:
        print(line)

