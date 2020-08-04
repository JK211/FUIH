#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.PublicKey import ECC
"""
这个模块用于仿真切片服务提供商的A3VI，用来处理Operator发来的初步的授权信息，验证后并对PST进行授权
生成一个成品票据ST，并上链存储

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
from solcrypto.pysolcrypto.aosring import aosring_randkeys, aosring_check, aosring_sign
from sslcrypto.fallback._util import int_to_bytes, bytes_to_int
import settings
# from results_record.global_dict import gol
# gol = gol()

def A3VI_func():
    curve = sslcrypto.ecc.get_curve('prime256v1')
    KeyTrans = key_type_transform.KeyTrans()   # 注意示例化！！！
    # Ring_Group = Ring_Group()  #  记得实例化
    ChameleonHash = ChameleonHash_ECC.ChameleonHash()
    # ************************UDP服务器端编程*********************************
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 12345))  # 绑定端口
    data, addr = s.recvfrom(4096)
    m_AUSF_A3VI = pickle.loads(data)   # 收到消息后，反序列化得到  {'ciphertext': ciphertext, 'signature': signature}
    signature_AUSF = m_AUSF_A3VI['signature']
    ciphertext_AUSF = m_AUSF_A3VI['ciphertext']
    print("***A3VI***收到的AUSF发送的消息<CText, E2, β>")
    start_reg = time.time()
    # *****************************A3VI读取Ope的公钥进行验签***********************************
    public_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_publickey.pem').read())
    x = public_key_raw.pointQ.x.__int__()
    y = public_key_raw.pointQ.y.__int__()
    pk_Ope = KeyTrans.b_public_key(x, y)

    s1 = hashlib.sha3_256()   #  这里利用sha256对密文进行哈希处理
    s1.update(ciphertext_AUSF)
    cipher_h = s1.hexdigest()
    b_cipher_h_AUSF = bytes(cipher_h, encoding='utf-8')   # 这里注意把 16进制的密文摘要转换为字节串，进行处理utf-8编码
    # assert True if curve.verify(signature_AUSF, b_cipher_h_AUSF, pk_Ope) else False
    # print('A3VI收到的签名为：', signature_AUSF)
    print('***A3VI***验签成功！！！') if curve.verify(signature_AUSF, b_cipher_h_AUSF, pk_Ope)is True else print('***A3VI***验签失败！！！')
    # ***************************A3VI利用自己的私钥开始解密，获取信息CH_UE,N,RG,PST****************************************
    private_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\A3VI_privatekey.pem').read()).d.__int__()
    sk = KeyTrans.b_private_key(private_key_raw)    # 注意！！！这是A3VI的私钥
    b_message_AUSF = curve.decrypt(ciphertext_AUSF, sk, algo='aes-256-ofb')
    message_AUSF = pickle.loads(b_message_AUSF)   #  这里获得AUSF转发的消息{'CH_UE': message_UE['CH_UE'], 'N': message_UE['N'], 'RG_Ope': keys, 'PST': PST}
    """
    这里A3VI把自己的公私钥混进环成员这里，在测试的时候，发现aosring的算法是基于secp256k1 (bitcoin)的，而我们其余的代码都是
    基于secp256r1的椭圆曲线，所以这里暂时随机生成密钥，用于环签名。
    """
    n = 10
    keys = aosring_randkeys(n)
    PST = message_AUSF['PST']
    b_PST = pickle.dumps(PST)
    msg = bytes_to_int(b_PST)
    # A3VI开始进行环签名，生成一个成品票据ST
    ST_all = aosring_sign(*keys, message=msg)
    ST = (ST_all[1], ST_all[2])
    end_reg = time.time()
    print('A3VI端服务注册阶段计算开销：', (end_reg-start_reg)*1000, 'ms')
    settings.result_dict['A3VI_Reg']=(end_reg - start_reg) * 1000
    print('///////////////', settings.result_dict)
    # gol.set_value('A3VI_Reg', (end_reg-start_reg)*1000)
    data_ST = {'CH_UE': message_AUSF['CH_UE'], 'N': message_AUSF['N'], 'RG_Ope': message_AUSF['RG_Ope'],
               'RG_A3VI': keys, 'ST': ST}
    print('***A3VI***生成票据ST，并把消息（CH_UE, N, T_Exp, RG_OPE, RG_A3VI, ST）上链成功！票据注册成功！')   #  到这一步后我们假装上链成功

    """
    这里A3VI把消息发布给区块链网络，由矿工对消息data_ST进行验证，利用'RG_Ope': message_AUSF['RG_Ope'], 'RG_A3VI'对票据ST进行验签，验签成功后，打包上链存储，
    生成交易的记录号 TXID_ST = b'8b60004928090023bef4292ed4e0e414a9f1eaa2d734d4b34beb5c6b2f33bb59'
    """
    TXID_ST = b'8b60004928090023bef4292ed4e0e414a9f1eaa2d734d4b34beb5c6b2f33bb59'
    T_Exp = time.time()

    """
    关于区块链共识以及上链存储的操作，考虑到我们的工作重点在于协议设计和分析，目前我们暂时不考虑搭建区块链部分的实验
    """
    # **********************UDP客户端编程***************************************
    # 我们这里把data_ST发送给EC，EC得到消息后，假装自己是上链查询到的数据
    b_data_ST = pickle.dumps(data_ST)
    m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    m.sendto(b_data_ST, ('127.0.0.1', 12346))
    # A3VI把数据上链成功后，把票据号TXID_ST和时间戳T_Exp发送给UE
    m_A3VI_UE = {'TXID_ST': TXID_ST, "T_Exp": T_Exp}
    b_m_A3VI_UE = pickle.dumps(m_A3VI_UE)
    m.sendto(b_m_A3VI_UE, ('127.0.0.1', 12347))
    print('服务注册阶段消息<TXDI_ST, T_Exp>字节数：', len(TXID_ST)+len(int_to_bytes(T_Exp.__int__(), 5)))




    # m.close()  m先不要close，等密钥协商材料发给UE后再close
    # print('EC根据TXDI_ST上链查询消息【实际是A3VI >> EC】')
    # print('发送消息成功，消息内容为：', b_m_AUSF_A3VI)


    # 等待接收EC发送给来的密钥协商材料
    agree_data, addr = s.recvfrom(4096)
    m_EC_A3VI = pickle.loads(agree_data)
    print("****A3VI****接收到的密钥协商材料为：", m_EC_A3VI)  # {'PID_UE': UE_EC['PID_UE'], 'm_UE': m_UE, 'A_UE': A_UE, 'B_UE': UE_EC['B_UE']}
    start_agree1 = time.time()
    x_A = m_EC_A3VI['A_UE'][0]
    y_A = m_EC_A3VI['A_UE'][1]
    A_UE = ECC.EccPoint(x_A, y_A)
    x_B = m_EC_A3VI['B_UE'][0]
    y_B = m_EC_A3VI['B_UE'][1]
    B_UE = ECC.EccPoint(x_B, y_B)
    # 开始计算临时的会话密钥
    order = ChameleonHash.order()
    alpha = random.randint(1, order - 1)    # 用于计算会话密钥
    beta = random.randint(1, order - 1)
    Y = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\A3VI_publickey.pem').read())  # 这里是Y_A3VI 即是读取的A3VI的公钥，是点值
    x_A3VI = private_key_raw # 这里private_key_raw为int值的原始私钥
    A_A3VI = Y.pointQ.__mul__(alpha)
    B_A3VI = Y.pointQ.__mul__(beta)
    temp = x_A3VI * (alpha + beta)
    K_A3VI = (A_UE + B_UE).__mul__(temp)
    print('***A3VI***计算出的会话密钥材料K为：', K_A3VI.xy)

    hash_m = [m_EC_A3VI['PID_UE'], m_EC_A3VI['m_UE'], K_A3VI.xy]
    b_hash_m = pickle.dumps(hash_m)
    # s1.update(b_hash_m[0:16])
    # SK_A3VI = s1.hexdigest()
    b_hash_m = bytes_to_int(pickle.dumps(hash_m))
    SK_A3VI = hash(b_hash_m)
    end_agree1 = time.time()
    print('***A3VI***计算出的会话密钥[Int类型]为：', SK_A3VI)

    # 计算出会话密钥后，把消息【假装通过EC】发送给UE
    print('+++3+++ A3VI >>>> UE 发送消息<A_A3VI, B_A3VI>')
    m_A3VI_UE = {'A_A3VI': A_A3VI.xy, 'B_A3VI': B_A3VI.xy}
    print('密钥协商阶段消息<A_UE,B_UE>字节数为：', 128)  # 这里我们不再计算，因为我们知道A_A3VI.xy B_A3VI.xy 分别为64个字节
    b_A3VI_UE = pickle.dumps(m_A3VI_UE)
    m.sendto(b_A3VI_UE, ('127.0.0.1', 12347))
    m.close()

    # 接收UE发过来的密钥协商应答消息ACK_UE
    ACK_data, addr = s.recvfrom(4096)
    s.close()
    ACK_UE = pickle.loads(ACK_data)
    start_agree2 = time.time()
    ACK_A3VI = hash(bytes_to_int(pickle.dumps([K_A3VI.xy, SK_A3VI])))
    # print('ACK_UE', ACK_UE)
    # print('ACK_A3VI', ACK_A3VI)
    if ACK_A3VI == ACK_UE:
        print('+++++++++++++++A3VI端密钥协商成功！！！++++++++++++++++++++++++++')
    else:
        print('++++++++++++++++++++++密钥协商失败！！++++++++++++++++++++++++++++++')
    end_agree2 = time.time()
    print('A3VI端密钥协商阶段计算开销为：', ((end_agree2-start_agree2)+(end_agree1-start_agree1)) * 1000, 'ms')
