#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.PublicKey import ECC
"""
这个模块用于仿真Operator里的主要的三个Network Function:{AMF, SMF, AUSF},
对UE发送的切片服务注册消息进行验证，并且利用环签名来形成初步的授权，产生半成品票据PST

2020/7/30
Jerry
"""
import sslcrypto
import random
import pickle
import socket
import hashlib
from Cyptology.ChameleonHash_ECC import ChameleonHash, CH
from Cyptology.key_type_transform import KeyTrans
from Cyptology.Ring_Group_Ope import Ring_Group
from solcrypto.pysolcrypto.aosring import aosring_randkeys, aosring_check, aosring_sign
from sslcrypto.fallback._util import int_to_bytes, bytes_to_int

curve = sslcrypto.ecc.get_curve('prime256v1')
KeyTrans = KeyTrans()   # 注意示例化！！！
Ring_Group = Ring_Group()  #  记得实例化
# ************************UDP服务器端编程*********************************
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 9999))  # 绑定端口
data, addr = s.recvfrom(4096)
s.close()
m_UE_AMF = pickle.loads(data)   # 收到消息后，反序列化得到  {'ciphertext': ciphertext, 'signature': signature}
signature_UE = m_UE_AMF['signature']
ciphertext_UE = m_UE_AMF['ciphertext']
print("------------Ope收到的UE发送的明文消息为：", m_UE_AMF)

# *****************************AMF读取用户的公钥进行验签***********************************
public_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\UE_publickey.pem').read())
x = public_key_raw.pointQ.x.__int__()
y = public_key_raw.pointQ.y.__int__()
pk_UE = KeyTrans.b_public_key(x, y)

s = hashlib.sha3_256()   #  这里利用sha256对密文进行哈希处理
s.update(ciphertext_UE)
cipher_h = s.hexdigest()
b_cipher_h_UE = bytes(cipher_h, encoding='utf-8')   # 这里注意把 16进制的密文摘要转换为字节串，进行处理utf-8编码
# assert True if curve.verify(signature_UE, b_cipher_h_UE, pk_UE) else False
print('验证UE的签名成功！！！') if curve.verify(signature_UE, b_cipher_h_UE, pk_UE) else print('验证UE的签名失败！！！')

# ************************************在Operator核心网内AMFciphertext_UE把消息转交给SMF处理*******************************************************
# ***************************SMF利用Ope的私钥开始解密，获取用户注册信息CH_UE，ID_UE,ID_A3VI****************************************
private_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_privatekey.pem').read()).d.__int__()
sk = KeyTrans.b_private_key(private_key_raw)    # 注意！！！这是Ope的私钥
b_message_UE = curve.decrypt(ciphertext_UE, sk, algo='aes-256-ofb')
message_UE = pickle.loads(b_message_UE)   #  这里获得UE的注册信息 {'CH_UE': CH_UE.CH(), 'N': N, 'ID_UE': ID_UE, 'ID_A3VI': ID_A3VI}
# print(message_UE)
# print(type(message_UE))

# *****************************************SMF把注册消息转发给AUSF处理********************************************************
# *************************读取Ope的公私钥，并混进环成员中，这里的公私钥形式为（x,y)  d  *********************************
# public_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_publickey.pem').read())
# x = public_key_raw.pointQ.x.__int__()
# y = public_key_raw.pointQ.y.__int__()
# pk_Ope = (x, y)
#
# private_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_privatekey.pem').read()).d.__int__()
# sk_Ope = private_key_raw    # 注意！！！这是Ope的私钥

"""
这里Ope把自己的公私钥混进环成员这里，在测试的时候，发现aosring的算法是基于secp256k1 (bitcoin)的，而我们其余的代码都是
基于secp256r1的椭圆曲线，所以这里暂时随机生成密钥，用于环签名。
"""
# *******************************************************************************************
n = 20
# keys = Ring_Group.generate_RG_with_input_key(n, pk_Ope, sk_Ope)   # 我们这里随机生成一些公私钥，假装找了一些其他的Ope成员形成环
keys = aosring_randkeys(n)

CH_N = {'CH_UE': message_UE['CH_UE'], 'N': message_UE['N']}
b_CH_N = pickle.dumps(CH_N)
s = hashlib.sha3_256()   #  这里利用sha256对密文进行哈希处理
s.update(b_CH_N)
b_CH_N_h_0x = s.hexdigest()
b_CH_N_h = bytes(b_CH_N_h_0x, encoding='utf')
msg = bytes_to_int(b_CH_N_h)
# AUSF开始进行环签名，生成一个半成品票据PST
PST_all = aosring_sign(*keys, message=msg)
PST = (PST_all[1], PST_all[2])  # 这里是签名的有效部分tees, cees[-1]  形式为 （（x, y）， z）
# AUSF把半成品票据和用户注册信息打包后，加密并签名发送给A3VI   CH_UE||N||RG||PST
message_AUSF = {'CH_UE': message_UE['CH_UE'], 'N': message_UE['N'], 'RG_Ope': keys, 'PST': PST}
b_message_AUSF = pickle.dumps(message_AUSF)

# 开始加密和签名
public_key_raw1 = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\A3VI_publickey.pem').read())
x1 = public_key_raw1.pointQ.x.__int__()
y1 = public_key_raw1.pointQ.y.__int__()
pk_A3VI = KeyTrans.b_public_key(x1, y1)

ciphertext = curve.encrypt(b_message_AUSF, pk_A3VI, algo='aes-256-ofb')    # 这里要用AUSF的公钥来加密
s1 = hashlib.sha3_256()   #  这里利用sha256对密文进行哈希处理
s1.update(ciphertext)
cipher_h = s1.hexdigest()
b_cipher_h = bytes(cipher_h, encoding='utf-8')   # 这里注意把 16进制的密文摘要转换为字节串，进行处理utf-8编码
signature = curve.sign(b_cipher_h, sk)   # 注意！！！这是Ope的私钥
print("Ope发送的签名为：", signature)
m_AUSF_A3VI = {'ciphertext': ciphertext, 'signature': signature}   # 这是AUSF需要发送的消息密文和签名
b_m_AUSF_A3VI = pickle.dumps(m_AUSF_A3VI)    # 消息序列化为字节串

# **********************UDP客户端编程***************************************
m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
m.sendto(b_m_AUSF_A3VI, ('127.0.0.1', 12345))
m.close()
print('AUSF发送的明文消息：', m_AUSF_A3VI)
print('发送消息成功，消息内容为：', b_m_AUSF_A3VI)