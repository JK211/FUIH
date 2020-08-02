#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
这个模块主要用于公钥值，私钥值的转换，因为从椭圆曲线上取出的公钥值是点值（x,y),私钥值是d,
我们在这里把公司要值转换为字节串
2020/7/31
Jerry
"""
import sslcrypto
from sslcrypto.fallback._util import int_to_bytes  # bytes_to_int
import struct


class KeyTrans(object):
    def __init__(self):
        self.__nid = 715
        self.__p = sslcrypto.ecc.get_curve('prime256v1').params['p']
        self.__len = (len(bin(self.__p).replace("0b", "")) + 7) // 8

    def __encode_public_key(self, x, y, is_compressed=True, raw=True):
        if raw:
            if is_compressed:
                return bytes([0x02 + (y[-1] % 2)]) + x
            else:
                return bytes([0x04]) + x + y
        else:
            return struct.pack("!HH", self.__nid, len(x)) + x + struct.pack("!H", len(y)) + y

    def b_private_key(self, private_key_raw):   # 注意这个函数的输入private_key_raw.d.__init__()，应该是私钥d的int值
        private_key = int_to_bytes(private_key_raw, self.__len)
        return private_key   # 返回私钥的字节串值

    def b_public_key(self, x, y):       #注意这个函数的输入应该为public_key_raw.pointQ.x.__int__()  y.__int__()  是公钥（x,y) int值
        b_x = int_to_bytes(x, self.__len)
        b_y = int_to_bytes(y, self.__len)
        return self.__encode_public_key(b_x, b_y)   # 返回公钥的字节串值

