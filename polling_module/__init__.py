#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
created by Kevin Ghorbani

Disclaimer: this is an open source software
            creator is not resposible for any
            hacking and poll manipulations.
"""

import metadata
import sys
import os
import random
import struct
import hashlib
import pickle
import time
import random
import string
import getpass
from Crypto import Random
from Crypto.Cipher import AES


__version__ = metadata.version
__author__ = metadata.authors[0]
__license__ = metadata.license
__copyright__ = metadata.copyright


User_hash_sha512 = hashlib.sha512('userhashpwd'.encode('utf8')).hexdigest()
iv = b'\xd6|\x05\x18\x14\xb2:\xb4<\xcc\x84\xa2P\xbd\xf2W'


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def try_except(f):
    def helper(*args):
        try:
            return f(*args)
        except BaseException:
            return None
    return helper

