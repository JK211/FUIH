#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
这个模块用于仿真UE变色龙哈希值CH_UE计算，以及用户注册信息N,ID生成
以及信息解密和签名

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
from sslcrypto.fallback._util import  bytes_to_int, int_to_bytes
from Cryptodome.PublicKey import ECC

def UE_func(m_dict):
    print('-----------------------------------------切片服务注册过程-----------------------------------------------')
    start_reg = time.time()
    #  ***************************开始计算变色龙哈希值*******************************
    ChameleonHash = ChameleonHash_ECC.ChameleonHash()   # 实例化对象，这一步注意不可少！！！
    KeyTrans = key_type_transform.KeyTrans()
    order = ChameleonHash.order()
    m0 = random.randint(1, order - 1)    # 这里m0 r0 是用户初始的两个变色龙哈希输入值
    r0 = random.randint(1, order - 1)    # 从（1，order)中随机选择两个数m0,r0作为我们变色龙哈希函数的初始输入
    CH_UE = ChameleonHash.Compute_CH(m0, r0)
    # print('计算好的哈希值和陷门', CH_UE.CH())   # CH（m0,r0) = mP + rY
    # print('陷门为：', CH_UE.trapdoor())   #陷门信息为（k,x）
    N = random.getrandbits(256)   # 获取256位随机位(二进制)的整数作为本次会话的会话号
    ID_UE = b'123456789abcdef'   # 用于模拟15位的SUPI / IMSI
    ID_A3VI = b'987654321abcdef'  # 类似的给A3VI分配一个ID号
    message_UE = {'CH_UE': CH_UE.CH(), 'N': N, 'ID_UE': ID_UE, 'ID_A3VI': ID_A3VI}  # 这是UE需要发送的消息明文
    b_message_UE = pickle.dumps(message_UE)   # 消息序列化为字节串
    # print(b_message_UE)
    # print(type(b_message_UE))
    # *************************读取UE的私钥和公钥*************************************
    private_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\UE_privatekey.pem').read()).d.__int__()
    sk = KeyTrans.b_private_key(private_key_raw)
    # *************************开始加密和签名************************************
    # 读取Ope的公钥
    public_key_raw_Ope = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_publickey.pem').read())
    x1 = public_key_raw_Ope.pointQ.x.__int__()
    y1 = public_key_raw_Ope.pointQ.y.__int__()
    pk_Ope = KeyTrans.b_public_key(x1, y1)
    curve = sslcrypto.ecc.get_curve('prime256v1')
    ciphertext = curve.encrypt(b_message_UE, pk_Ope, algo='aes-256-ofb')    # 这里要用Ope的公钥来加密
    h = hashlib.sha3_256()   #  这里利用sha256对密文进行哈希处理
    h.update(ciphertext)
    cipher_h = h.hexdigest()
    b_cipher_h = bytes(cipher_h, encoding='utf-8')   # 这里注意把 16进制的密文摘要转换为字节串，进行处理utf-8编码
    signature = curve.sign(b_cipher_h, sk)
    m_UE_AMF = {'ciphertext': ciphertext, 'signature': signature}   # 这是UE需要发送的消息密文和签名
    print('服务注册阶段消息<UText, E1, σ>字节数为：', len(ciphertext)+len(signature))
    m_dict['1'] = len(ciphertext)+len(signature)
    b_m_UE_AMF = pickle.dumps(m_UE_AMF)    # 消息序列化为字节串
    # print('序列化后的消息<UText, E1, σ>字节数为：', len(b_m_UE_AMF))
    end_reg = time.time()
    print('UE端服务注册阶段计算开销：', (end_reg-start_reg)*1000, 'ms')
    m_dict['UE_Reg'] = (end_reg-start_reg)*1000
    # print(m_UE_AMF)
    # print(b_m_UE_AMF)
    # **********************UDP客户端编程【发送给AMF消息进行注册】***************************************
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b_m_UE_AMF, ('127.0.0.1', 9999))
    # s.close()  发送完ACK_UE再关闭
    print('---1---  UE  >>>>  AMF  发送消息<UText, E1, σ>')
    # print('发送消息成功，消息内容为：', b_m_UE_AMF)
    # ************************UDP服务器端编程*********************************
    v = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    v.bind(('127.0.0.1', 12347))  # 绑定端口

    # print('007data:', pickle.loads(data))
    # v.close()  收到密钥协商材料后再close
    # TXID_ST = b'8b60004928090023bef4292ed4e0e414a9f1eaa2d734d4b34beb5c6b2f33bb59'

    data_A3VI_UE, addr = v.recvfrom(4096)  # 接收A3VI返回的注册后的确认消息<TXID_UE, T_Exp>

    m_A3VI_UE = pickle.loads(data_A3VI_UE)
    # print('007UE收到的注册确认消息TXID_UE：', m_A3VI_UE)
    TXID_ST = m_A3VI_UE['TXID_ST']
    # end_reg = time.time()
    # print('整个切片服务注册阶段计算开销为：', (end_reg-start_reg) * 1000, 'ms')

    # **********************UDP客户端编程【发送给EC消息进行认证】***************************************
    start_auth = time.time()
    SST = 0b10110001
    w = {'SST': SST, 'ID_A3VI': ID_A3VI}
    b_w = pickle.dumps(w)
    # 这里生成 Hidden_Alloewed_S_NSSAI
    k = hashlib.sha3_256()   #  这里利用sha256对密文进行哈希处理
    k.update(b_w)
    w_h = k.hexdigest()
    b_w_h = bytes(w_h, encoding='utf-8')   # 这里注意把 16进制的密文摘要转换为字节串，进行处理utf-8编码
    Hidden_Allowed_S_NSSAI = b_w_h

    print('+++++++++++++++++++++++++++++++++++++++++++Inter-slice handover Authenticaion Phase++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    PID_UE = b'123456789abcdef12345'   # 用户自己随机选择一个20位的假名
    alpha = random.randint(1, order - 1)    # 用于计算变色龙哈希碰撞
    beta = random.randint(1, order - 1)
    Y = ChameleonHash.get_Y()

    A_UE = Y.pointQ.__mul__(alpha)  # A_UE = alpha * Y
    B_UE = Y.pointQ.__mul__(beta)   # B_UE = beta * Y

    T_Curr = time.time()
    m = {'PID_UE': PID_UE, 'A_UE': A_UE.xy, 'B_UE': B_UE.xy, "T_Curr": T_Curr}
    b_m = pickle.dumps(m)
    h = hashlib.sha3_256()
    h.update(b_m)
    m_h = h.hexdigest()
    b_m_h = bytes(m_h, encoding='utf-8')
    gamma = bytes_to_int(b_m_h)

    k = CH_UE.trapdoor()[0]
    x = CH_UE.trapdoor()[1]

    r1 = alpha * gamma
    m1 = (k - r1*x + order) % order
    end_auth = time.time()
    print('UE端在服务认证阶段的计算开销为：', (end_auth-start_auth) * 1000, 'ms')
    m_dict['UE_Auth'] = (end_auth-start_auth) * 1000
    # # TXID_ST = b'8b60004928090023bef4292ed4e0e414a9f1eaa2d734d4b34beb5c6b2f33bb59'
    #
    # data_A3VI_UE, addr = v.recvfrom(4096)  # 接收A3VI返回的注册后的确认消息<TXID_UE, T_Exp>
    #
    # m_A3VI_UE = pickle.loads(data_A3VI_UE)
    # # print('007UE收到的注册确认消息TXID_UE：', m_A3VI_UE)
    # TXID_ST = m_A3VI_UE['TXID_ST']
    # end_reg = time.time()
    # print('整个切片服务注册阶段计算开销为：', (end_reg-start_reg) * 1000, 'ms')


    data, addr = v.recvfrom(4096)
    m_UE_EC = {'Hidden_Allowed_S_NSSAI': Hidden_Allowed_S_NSSAI, 'PID_UE': PID_UE, 'A_UE': A_UE.xy, 'B_UE': B_UE.xy,
               'm_UE': m1, 'T_Curr': T_Curr, 'TXID_ST': TXID_ST}
    b_m_UE_EC = pickle.dumps(m_UE_EC)
    print('+++1+++  UE >>>> EC 发送认证消息<Hidden_Allowed_S_NSSAI, PID_UE, A_UE, B_UE, m_UE, T_Curr, TXID_ST>')
    # print('服务认证阶段消息<Hidden_Allowed_S_NSSAI, PID_UE, A_UE, B_UE, m_UE, T_Curr, TXID_ST>字节数：', len(Hidden_Allowed_S_NSSAI) +
    #       len(PID_UE) + 64 + 64 +len(int_to_bytes(m1, 5))+len(int_to_bytes(T_Curr.__int__(), 5))+len(TXID_ST))
    print('服务认证阶段消息<Hidden_Allowed_S_NSSAI, PID_UE, A_UE, B_UE, m_UE, T_Curr, TXID_ST>字节数：',
          len(Hidden_Allowed_S_NSSAI) +
          len(PID_UE) + 64 + 64 + m1.bit_length()/8 + T_Curr.__int__().bit_length()/8 + len(TXID_ST))
    m_dict['4'] = len(Hidden_Allowed_S_NSSAI) + len(PID_UE) + 64 + 64 + m1.bit_length()/8 + T_Curr.__int__().bit_length()/8 + len(TXID_ST)
    if data == b'start':
        l = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        l.sendto(b_m_UE_EC, ('127.0.0.1', 12346))
        l.close()


    ack_data, addr = v.recvfrom(1024)
    DoKeyAgreement = pickle.loads(ack_data)
    if DoKeyAgreement:
        print('***UE***收到密钥协商提示为True。')
    else:
        print('***UE***收到密钥协商提示为False。')
    # end_auth =time.time()
    # print('整个服务认证阶段计算开销为：', (end_auth - start_auth) * 1000, 'ms')

    # print('发送消息成功，消息内容为：', b_m_UE_EC)
    # 接收A3VI密钥协商材料，并计算协商材料K值
    agree_data, addr = v.recvfrom(4096)
    A3VI_UE = pickle.loads(agree_data)  # {'A_A3VI': A_A3VI, 'B_A3VI': B_A3VI}
    print('***UE***接收到的A3VI的密钥协商材料为：', A3VI_UE)
    start_agree = time.time()
    x_A = A3VI_UE['A_A3VI'][0]
    y_A = A3VI_UE['A_A3VI'][1]
    A_A3VI = ECC.EccPoint(x_A, y_A)
    x_B = A3VI_UE['B_A3VI'][0]
    y_B = A3VI_UE['B_A3VI'][1]
    B_A3VI = ECC.EccPoint(x_B, y_B)
    x_UE = ChameleonHash.get_x().__int__()
    K_UE = (A_A3VI + B_A3VI).__mul__(x_UE * (alpha + beta))
    print('***UE***计算出的密钥协商材料K为：', K_UE.xy)
    # 开始计算协商密钥
    hash_m = [PID_UE, m1, K_UE.xy]
    # b_hash_m = pickle.dumps(hash_m)
    # print('哈希前的长度', len(b_hash_m))
    # h.update(b_hash_m[0:16])
    # SK_A3VI = h.hexdigest()
    # print(b_hash_m)
    b_hash_m = bytes_to_int(pickle.dumps(hash_m))
    SK_A3VI = hash(b_hash_m)
    end_agree = time.time()
    print('UE端密钥协商阶段计算开销为：', (end_agree-start_agree)*1000, 'ms')
    m_dict['UE_KA'] =  (end_agree-start_agree)*1000
    # SK = hash(b_hash_m)
    print('***UE***计算出的会话密钥[Int类型]为：', SK_A3VI)
    # print(SK)

    # 【通过EC】发送ACK_UE消息给A3VI
    hash_m1 = [K_UE.xy, SK_A3VI]
    ACK = hash(bytes_to_int(pickle.dumps(hash_m1)))
    b_ACK = pickle.dumps(ACK)
    s.sendto(b_ACK, ('127.0.0.1', 12345))
    s.close()
    print('+++4+++ UE >>>> A3VI 发送消息ACK')
    # print(type(ACK))
    print('密钥协商阶段消息<ACK>字节数为：', ACK.bit_length()/8)
    m_dict['7'] = ACK.bit_length()/8
    print('++++++++++++++++++++UE端密钥协商完成！！！++++++++++++++++++++++++')
