#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.PublicKey import ECC
"""
这个模块用于仿真EC，对用户片间换手认证进行验证
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
from sslcrypto.fallback._util import int_to_bytes, bytes_to_int

ChameleonHash = ChameleonHash()   # 实例化对象，这一步注意不可少！！！
KeyTrans = KeyTrans()
order = ChameleonHash.order()

# ************************UDP服务器端编程*********************************
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 12346))  # 绑定端口
data, addr = s.recvfrom(8192)    # 接收A3VI发来的消息
# s.close()
data_ST = pickle.loads(data)   # 收到消息后，反序列化得到  {'CH_UE': message_AUSF['CH_UE'], 'N': message_AUSF['N'], 'RG_Ope': message_AUSF['RG_Ope'], 'RG_A3VI': keys, 'ST': ST}
CH_UE = data_ST['CH_UE']    # 这里假装是用后面接收到的TXID_ST上链查询到的CH_UE值

# **********************UDP客户端编程【发送消息给UE，提示其开始认证过程】***************************************
message = b'start'
t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
t.sendto(message, ('127.0.0.1', 12347))
t.close()

"""
UE_EC = {'Hidden_Allowed_S_NSSAI': Hidden_Allowed_S_NSSAI, 'PID_UE': PID_UE, 'A_UE': A_UE.xy, 'B_UE': B_UE.xy,
           'm_UE': m1, 'T_Curr': T_Curr, 'TXID_ST': TXID_ST}
"""
data1, addr1 = s.recvfrom(8192)
UE_EC = pickle.loads(data1)
print('EC收到的UE的认证消息为', UE_EC)
s.close()

m = {'PID_UE': UE_EC['PID_UE'], 'A_UE': UE_EC['A_UE'], 'B_UE': UE_EC['B_UE'], "T_Curr": UE_EC['T_Curr']}
b_m = pickle.dumps(m)
h = hashlib.sha3_256()
h.update(b_m)
m_h = h.hexdigest()
b_m_h = bytes(m_h, encoding='utf-8')
gamma = bytes_to_int(b_m_h)

m_UE = UE_EC['m_UE']
A_UE = UE_EC['A_UE']
x = A_UE[0]
y = A_UE[1]
A = ECC.EccPoint(x, y)
P = ECC._curves['P-256'].G
CH_EC = P.__mul__(m_UE) + A.__mul__(gamma)
print('EC根据用户发送的TXID_ST上链查询到的哈希值：', CH_UE)
print('EC根据接收到的消息计算出的哈希值：', CH_EC.xy)

print('****************！！！EC端验证碰撞成功！！！*********************') if CH_EC.xy == CH_UE else print('碰撞失败')


#   提示A3VI开始密钥协商，并将一些密钥协商材料转交给A3VI
m_EC_A3VI = {'PID_UE': UE_EC['PID_UE'], 'm_UE': m_UE, 'A_UE': A_UE, 'B_UE': UE_EC['B_UE']}
b_m_EC_A3VI = pickle.dumps(m_EC_A3VI)
# **********************UDP客户端编程【发送消息给A3VI，提示其开始密钥协商过程】***************************************
tt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tt.sendto(b_m_EC_A3VI, ('127.0.0.1', 12345))
tt.close()
