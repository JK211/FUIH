#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.PublicKey import ECC
import time
"""
该部分用于系统初始化，产生UE，Operator,A3VI的公私钥对，并形成证书存储。
"""
print("---------------开始生成公私钥文件-------------------")
t1 = time.clock()
key_UE = ECC.generate(curve='secp256r1')
print("CPU执行时间：", (time.clock()-t1)*1000, 'ms')
key_Ope = ECC.generate(curve='secp256r1')
key_A3VI = ECC.generate(curve='secp256r1')

f = open(r'D:\PythonProject\FUIH\ECC_file_keys\UE_privatekey.pem', 'wt')
f.write(key_UE.export_key(format='PEM'))
f.close()

t = open(r'D:\PythonProject\FUIH\ECC_file_keys\UE_publickey.pem', 'wt')
publickey = key_UE.public_key()
t.write(publickey.export_key(format='PEM'))
t.close()
print()

f = open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_privatekey.pem', 'wt')
f.write(key_Ope.export_key(format='PEM'))
f.close()

t = open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_publickey.pem', 'wt')
publickey = key_Ope.public_key()
t.write(publickey.export_key(format='PEM'))
t.close()

f = open(r'D:\PythonProject\FUIH\ECC_file_keys\A3VI_privatekey.pem', 'wt')
f.write(key_A3VI.export_key(format='PEM'))
f.close()

t = open(r'D:\PythonProject\FUIH\ECC_file_keys\A3VI_publickey.pem', 'wt')
publickey = key_A3VI.public_key()
t.write(publickey.export_key(format='PEM'))
t.close()


# print("---------------公私钥文件内容展示-------------------")
# f = open(r'D:\PythonProject\BiHand\ECC_file\myprivatekey.pem', 'rt')
# key = ECC.import_key(f.read())
# print('我们生成的ECC密钥文件为：', key)
# print('我们的密钥文件包含私钥吗？', key.has_private())
# print('我们的ECC公钥为：', key.public_key())

