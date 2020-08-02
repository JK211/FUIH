#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.PublicKey import ECC
"""
用于测试 自己生成密钥混入 自动生成的环成员 并完成签名和验签
2020/7/30
Jerry
"""
from solcrypto.pysolcrypto.aosring import aosring_randkeys, aosring_check, aosring_sign
import time
from Cyptology.Ring_Group_Ope import Ring_Group
from Cyptology.key_type_transform import KeyTrans
from sslcrypto.fallback._util import int_to_bytes, bytes_to_int

Ring_Group = Ring_Group()  #  记得实例化
KeyTrans = KeyTrans()
# *************************读取Ope的公私钥，并混进环成员中*********************************
public_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_publickey.pem').read())
x = public_key_raw.pointQ.x.__int__()
y = public_key_raw.pointQ.y.__int__()
pk_Ope = (x, y)

private_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_privatekey.pem').read()).d.__int__()
sk_Ope = private_key_raw    # 注意！！！这是Ope的私钥

n = 10
keys = Ring_Group.generate_RG_with_input_key(n, pk_Ope, sk_Ope)

print('环中成员个数有：', len(keys[0]))
print('环成员[公钥值]为：', keys[0])
print('签名者[公钥+私钥]为：', keys[1])

# keys = aosring_randkeys(n)

b_msg = b'This is 225!'
msg = bytes_to_int(b_msg)
print(msg)

# msg = 123456
RC = aosring_sign(*keys, message=msg)
print('环签名为：', RC)