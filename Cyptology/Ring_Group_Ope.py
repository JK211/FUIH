#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.PublicKey import ECC
import time
import random
"""
该部分用于生成Ope的环成员公私钥，并且保存为形式为（[pk1,pk2,……,pkn]，（（pki）,ski））,其中pk = (x,y) ski是一个int值
"""
class Ring_Group(object):
    def __init__(self):
        pass

    def generate_RG_with_input_key(self, n, pk, sk):
        self.__pkeys = []
        for i in range(0, n-1):
            self.__key = ECC.generate(curve='secp256r1')
            self.__pkeys.append((self.__key.pointQ.x.__int__(),self.__key.pointQ.y.__int__()))
        self.__pkeys.append(pk)
        random.shuffle(self.__pkeys)
        return self.__pkeys, (pk, sk)




