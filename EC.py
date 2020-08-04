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
import time
from Cyptology import ChameleonHash_ECC,key_type_transform
from sslcrypto.fallback._util import int_to_bytes, bytes_to_int
import settings

def EC_func():
    ChameleonHash = ChameleonHash_ECC.ChameleonHash()   # 实例化对象，这一步注意不可少！！！
    KeyTrans = key_type_transform.KeyTrans()
    order = ChameleonHash.order()

    # ************************UDP服务器端编程*********************************
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 12346))  # 绑定端口
    data, addr = s.recvfrom(8192)    # 接收A3VI发来的消息
    # s.close()
    data_ST = pickle.loads(data)   # 收到消息后，反序列化得到  {'CH_UE': message_AUSF['CH_UE'], 'N': message_AUSF['N'], 'RG_Ope': message_AUSF['RG_Ope'], 'RG_A3VI': keys, 'ST': ST}
    CH_UE = data_ST['CH_UE']    # 这里假装是用后面接收到的TXID_ST上链查询到的CH_UE值
    # print('***EC***参与区块链共识，备份链上数据【包含CH_UE】！！！')
    # **********************UDP客户端编程【发送消息给UE，提示其开始认证过程】***************************************
    print('EC >> UE 开始认证')
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
    # print('***EC***收到的UE的认证消息:', UE_EC)
    print('***EC***收到的UE的认证消息')
    start_auth = time.time()
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

    B_UE = UE_EC['B_UE']
    x_B = B_UE[0]
    y_B = B_UE[1]
    B = ECC.EccPoint(x_B, y_B)
    P = ECC._curves['P-256'].G
    CH_EC = P.__mul__(m_UE) + A.__mul__(gamma)
    print('***EC***根据用户发送的TXID_ST上链查询到的哈希值：', CH_UE)
    print('***EC***根据接收到的消息计算出的哈希值：', CH_EC.xy)
    print('****************！！！EC端验证碰撞成功！！！*********************') if CH_EC.xy == CH_UE else print('碰撞失败')
    end_auth = time.time()
    print('EC端在服务认证阶段的计算开销：', (end_auth-start_auth) * 1000, 'ms')


    #   提示A3VI开始密钥协商，并将一些密钥协商材料转交给A3VI
    m_EC_A3VI = {'PID_UE': UE_EC['PID_UE'], 'm_UE': m_UE, 'A_UE': A_UE, 'B_UE': UE_EC['B_UE']}
    b_m_EC_A3VI = pickle.dumps(m_EC_A3VI)
    DokeyAgreement = True
    b_DokeyAgreement = pickle.dumps(DokeyAgreement)
    # **********************UDP客户端编程【发送消息给A3VI，提示其开始密钥协商过程】***************************************
    print('+++2+++ UE <<<< EC >>>> A3VI  提示双方开始密钥协商过程')
    # print('服务认证阶段消息<ACK,PID_UE,m_UE,A_UE,B_UE>字节数为：', len(UE_EC['PID_UE']) + len(int_to_bytes(m_UE, 5)) + len(A.xy) + len(B.xy))
    print('服务认证阶段消息<ACK,PID_UE,m_UE,A_UE,B_UE>字节数为：', len(UE_EC['PID_UE']) + len(int_to_bytes(m_UE, 32)) + 64 + 64)
    # print('序列化后的服务认证阶段消息<ACK,PID_UE,m_UE,A_UE,B_UE>字节数为：', len(b_m_EC_A3VI))
    tt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tt.sendto(b_m_EC_A3VI, ('127.0.0.1', 12345))
    tt.sendto(b_DokeyAgreement, ('127.0.0.1', 12347))
    tt.close()
