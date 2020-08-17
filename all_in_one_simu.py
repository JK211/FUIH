from multiprocessing import *
import sslcrypto
import random
import pickle
import socket
import hashlib
import time
from Cyptology import ChameleonHash_ECC,key_type_transform
from solcrypto.pysolcrypto.aosring import aosring_randkeys, aosring_check, aosring_sign
from sslcrypto.fallback._util import int_to_bytes, bytes_to_int
from Cryptodome.PublicKey import ECC


def A3VI_func(m_dict):
    curve = sslcrypto.ecc.get_curve('prime256v1')
    KeyTrans = key_type_transform.KeyTrans()   # 注意示例化！！！
    ChameleonHash = ChameleonHash_ECC.ChameleonHash()
    # ************************UDP服务器端编程*********************************
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 12345))  # 绑定端口
    data, addr = s.recvfrom(4096)
    m_AUSF_A3VI = pickle.loads(data)   # 收到消息后，反序列化得到  {'ciphertext': ciphertext, 'signature': signature}
    signature_AUSF = m_AUSF_A3VI['signature']
    ciphertext_AUSF = m_AUSF_A3VI['ciphertext']
    print("***A3VI***收到的AUSF发送的消息<CText, E2, β>")
    start_reg = time.clock()
    # *****************************A3VI读取Ope的公钥进行验签***********************************
    public_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_publickey.pem').read())
    x = public_key_raw.pointQ.x.__int__()
    y = public_key_raw.pointQ.y.__int__()
    pk_Ope = KeyTrans.b_public_key(x, y)

    s1 = hashlib.sha3_256()   #  这里利用sha256对密文进行哈希处理
    s1.update(ciphertext_AUSF)
    cipher_h = s1.hexdigest()
    b_cipher_h_AUSF = bytes(cipher_h, encoding='utf-8')   # 这里注意把 16进制的密文摘要转换为字节串，进行处理utf-8编码
    # print('***A3VI***验签成功！！！') if curve.verify(signature_AUSF, b_cipher_h_AUSF, pk_Ope)is True else print('***A3VI***验签失败！！！')
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
    end_reg = time.clock()
    print('A3VI端服务注册阶段计算开销：', (end_reg-start_reg)*1000, 'ms')
    m_dict['A3VI_Reg']=(end_reg - start_reg) * 1000
    # gol.set_value('A3VI_Reg', (end_reg-start_reg)*1000)
    # data_ST = {'CH_UE': message_AUSF['CH_UE'], 'N': message_AUSF['N'], 'RG_Ope': message_AUSF['RG_Ope'],
    #            'RG_A3VI': keys, 'ST': ST}
    data_ST = {'CH_UE': message_AUSF['CH_UE'], 'N': message_AUSF['N'], 'RG_A3VI': keys, 'ST': ST}
    # print('***A3VI***生成票据ST，并把消息（CH_UE, N, T_Exp, RG_OPE, RG_A3VI, ST）上链成功！票据注册成功！')   #  到这一步后我们假装上链成功

    """
    这里A3VI把消息发布给区块链网络，由矿工对消息data_ST进行验证，利用'RG_Ope': message_AUSF['RG_Ope'], 'RG_A3VI'对票据ST进行验签，验签成功后，打包上链存储，
    生成交易的记录号 TXID_ST = b'8b60004928090023bef4292ed4e0e414a9f1eaa2d734d4b34beb5c6b2f33bb59'
    """
    TXID_ST = b'8b60004928090023bef4292ed4e0e414a9f1eaa2d734d4b34beb5c6b2f33bb59'
    T_Exp = time.clock()

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
    # print("****A3VI****接收到的密钥协商材料为：", m_EC_A3VI)  # {'PID_UE': UE_EC['PID_UE'], 'm_UE': m_UE, 'A_UE': A_UE, 'B_UE': UE_EC['B_UE']}
    start_agree1 = time.clock()
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
    # print('***A3VI***计算出的会话密钥材料K为：', K_A3VI.xy)

    hash_m = [m_EC_A3VI['PID_UE'], m_EC_A3VI['m_UE'], K_A3VI.xy]
    b_hash_m = pickle.dumps(hash_m)
    # s1.update(b_hash_m[0:16])
    # SK_A3VI = s1.hexdigest()
    b_hash_m = bytes_to_int(pickle.dumps(hash_m))
    SK_A3VI = hash(b_hash_m)
    end_agree1 = time.clock()
    # print('***A3VI***计算出的会话密钥[Int类型]为：', SK_A3VI)

    # 计算出会话密钥后，把消息【假装通过EC】发送给UE
    # print('+++3+++ A3VI >>>> UE 发送消息<A_A3VI, B_A3VI>')
    m_A3VI_UE = {'A_A3VI': A_A3VI.xy, 'B_A3VI': B_A3VI.xy}
    print('密钥协商阶段消息<A_UE,B_UE>字节数为：', 128)  # 这里我们不再计算，因为我们知道A_A3VI.xy B_A3VI.xy 分别为64个字节
    b_A3VI_UE = pickle.dumps(m_A3VI_UE)
    m.sendto(b_A3VI_UE, ('127.0.0.1', 12347))
    m.close()

    # 接收UE发过来的密钥协商应答消息ACK_UE
    ACK_data, addr = s.recvfrom(4096)
    s.close()
    ACK_UE = pickle.loads(ACK_data)
    start_agree2 = time.clock()
    ACK_A3VI = hash(bytes_to_int(pickle.dumps([K_A3VI.xy, SK_A3VI])))
    # print('ACK_UE', ACK_UE)
    # print('ACK_A3VI', ACK_A3VI)
    if ACK_A3VI == ACK_UE:
        pass
        # print('+++++++++++++++A3VI端密钥协商成功！！！++++++++++++++++++++++++++')
    else:
        pass
        # print('++++++++++++++++++++++密钥协商失败！！++++++++++++++++++++++++++++++')
    end_agree2 = time.clock()
    print('A3VI端密钥协商阶段计算开销为：', ((end_agree2-start_agree2)+(end_agree1-start_agree1)) * 1000, 'ms')

def EC_func(m_dict):
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
    # print('EC >> UE 开始认证')
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
    # print('***EC***收到的UE的认证消息')
    start_auth = time.clock()
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
    # print('***EC***根据用户发送的TXID_ST上链查询到的哈希值：', CH_UE)
    # print('***EC***根据接收到的消息计算出的哈希值：', CH_EC.xy)
    # print('****************！！！EC端验证碰撞成功！！！*********************') if CH_EC.xy == CH_UE else print('碰撞失败')
    end_auth = time.clock()
    print('EC端在服务认证阶段的计算开销：', (end_auth-start_auth) * 1000, 'ms')


    #   提示A3VI开始密钥协商，并将一些密钥协商材料转交给A3VI
    m_EC_A3VI = {'PID_UE': UE_EC['PID_UE'], 'm_UE': m_UE, 'A_UE': A_UE, 'B_UE': UE_EC['B_UE']}
    b_m_EC_A3VI = pickle.dumps(m_EC_A3VI)
    DokeyAgreement = True
    b_DokeyAgreement = pickle.dumps(DokeyAgreement)
    # **********************UDP客户端编程【发送消息给A3VI，提示其开始密钥协商过程】***************************************
    # print('+++2+++ UE <<<< EC >>>> A3VI  提示双方开始密钥协商过程')
    # print('服务认证阶段消息<ACK,PID_UE,m_UE,A_UE,B_UE>字节数为：', len(UE_EC['PID_UE']) + len(int_to_bytes(m_UE, 5)) + len(A.xy) + len(B.xy))
    print('服务认证阶段消息<ACK,PID_UE,m_UE,A_UE,B_UE>字节数为：', len(UE_EC['PID_UE']) + len(int_to_bytes(m_UE, 32)) + 64 + 64)
    tt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tt.sendto(b_m_EC_A3VI, ('127.0.0.1', 12345))
    tt.sendto(b_DokeyAgreement, ('127.0.0.1', 12347))
    tt.close()

def Ope_func(m_dict):
    curve = sslcrypto.ecc.get_curve('prime256v1')
    KeyTrans = key_type_transform.KeyTrans()   # 注意示例化！！！
    # ************************UDP服务器端编程*********************************
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 9999))  # 绑定端口
    data, addr = s.recvfrom(4096)
    s.close()
    m_UE_AMF = pickle.loads(data)   # 收到消息后，反序列化得到  {'ciphertext': ciphertext, 'signature': signature}
    signature_UE = m_UE_AMF['signature']
    ciphertext_UE = m_UE_AMF['ciphertext']
    print("***AMF***收到的UE发送的消息<UText, E, σ>")
    start_reg = time.clock()
    # *****************************AMF读取用户的公钥进行验签***********************************
    public_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\UE_publickey.pem').read())
    x = public_key_raw.pointQ.x.__int__()
    y = public_key_raw.pointQ.y.__int__()
    pk_UE = KeyTrans.b_public_key(x, y)

    s = hashlib.sha3_256()   #  这里利用sha256对密文进行哈希处理
    s.update(ciphertext_UE)
    cipher_h = s.hexdigest()
    b_cipher_h_UE = bytes(cipher_h, encoding='utf-8')   # 这里注意把 16进制的密文摘要转换为字节串，进行处理utf-8编码
    # print('***AMF***验证UE的签名成功！！！') if curve.verify(signature_UE, b_cipher_h_UE, pk_UE) else print('***AMF***验证UE的签名失败！！！')
    # ************************************在Operator核心网内AMF把ciphertext_UE消息转交给SMF处理*******************************************************
    # ***************************SMF利用Ope的私钥开始解密，获取用户注册信息CH_UE，ID_UE,ID_A3VI****************************************
    # print('---2---  AMF  >>  SMF  发送消息<UText, E>')
    print('服务注册阶段消息<UText, E>字节数为：', len(ciphertext_UE))
    private_key_raw = ECC.import_key(open(r'D:\PythonProject\FUIH\ECC_file_keys\Ope_privatekey.pem').read()).d.__int__()
    sk = KeyTrans.b_private_key(private_key_raw)    # 注意！！！这是Ope的私钥
    b_message_UE = curve.decrypt(ciphertext_UE, sk, algo='aes-256-ofb')
    message_UE = pickle.loads(b_message_UE)   #  这里获得UE的注册信息 {'CH_UE': CH_UE.CH(), 'N': N, 'ID_UE': ID_UE, 'ID_A3VI': ID_A3VI}
    # print('***SMF***解密UText为：', message_UE)
    # *****************************************SMF把注册消息转发给AUSF处理********************************************************
    # print('---3---  SMF  >>  AUSF  发送消息<CH_UE, N, ID_UE, ID_A3VI>')
    print('服务注册阶段消息<CH_UE, N, ID_UE, ID_A3VI>字节数为：', len(message_UE['CH_UE']) + len(int_to_bytes(message_UE['N'], 32))
                                                         + len(message_UE['ID_UE'])+len(message_UE['ID_A3VI']))
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
    n = 10
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
    # print('***AUSF***生成半成品票据PST')
    # AUSF把半成品票据和用户注册信息打包后，加密并签名发送给A3VI   CH_UE||N||RG||PST
    # message_AUSF = {'CH_UE': message_UE['CH_UE'], 'N': message_UE['N'], 'RG_Ope': keys, 'PST': PST}
    message_AUSF = {'CH_UE': message_UE['CH_UE'], 'N': message_UE['N'], 'PST': PST}
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
    # print("Ope发送的签名为：", signature)
    m_AUSF_A3VI = {'ciphertext': ciphertext, 'signature': signature}   # 这是AUSF需要发送的消息密文和签名
    b_m_AUSF_A3VI = pickle.dumps(m_AUSF_A3VI)    # 消息序列化为字节串
    end_reg = time.clock()
    print('Ope端服务注册阶段计算开销为：', (end_reg-start_reg)*1000, 'ms')
    m_dict['Ope_Reg'] = (end_reg-start_reg)*1000
    # gol.set_value('Ope_Reg', (end_reg-start_reg)*1000)
    # **********************UDP客户端编程***************************************
    # print('---4---  AUSF  >>>>  A3VI  发送消息<CText, E2, β>')
    print('服务注册阶段消息<CText, E2, β>字节数为：', len(ciphertext)+len(signature))
    m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    m.sendto(b_m_AUSF_A3VI, ('127.0.0.1', 12345))
    m.close()
    # print('AUSF发送的明文消息：', m_AUSF_A3VI)
    # print('发送消息成功，消息内容为：', b_m_AUSF_A3VI)


def UE_func(m_dict):
    print('-----------------------------------------切片服务注册过程-----------------------------------------------')
    start_reg = time.clock()
    #  ***************************开始计算变色龙哈希值*******************************
    ChameleonHash = ChameleonHash_ECC.ChameleonHash()   # 实例化对象，这一步注意不可少！！！
    KeyTrans = key_type_transform.KeyTrans()
    order = ChameleonHash.order()
    m0 = random.randint(1, order - 1)    # 这里m0 r0 是用户初始的两个变色龙哈希输入值
    r0 = random.randint(1, order - 1)    # 从（1，order)中随机选择两个数m0,r0作为我们变色龙哈希函数的初始输入
    CH_UE = ChameleonHash.Compute_CH(m0, r0)
    N = random.getrandbits(256)   # 获取256位随机位(二进制)的整数作为本次会话的会话号
    ID_UE = b'123456789abcdef'   # 用于模拟15位的SUPI / IMSI
    ID_A3VI = b'987654321abcdef'  # 类似的给A3VI分配一个ID号
    message_UE = {'CH_UE': CH_UE.CH(), 'N': N, 'ID_UE': ID_UE, 'ID_A3VI': ID_A3VI}  # 这是UE需要发送的消息明文
    b_message_UE = pickle.dumps(message_UE)   # 消息序列化为字节串
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
    b_m_UE_AMF = pickle.dumps(m_UE_AMF)    # 消息序列化为字节串
    end_reg = time.clock()
    print('UE端服务注册阶段计算开销：', (end_reg-start_reg)*1000, 'ms')
    m_dict['UE_Reg'] = (end_reg-start_reg)*1000
    # **********************UDP客户端编程【发送给AMF消息进行注册】***************************************
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b_m_UE_AMF, ('127.0.0.1', 9999))
    # print('---1---  UE  >>>>  AMF  发送消息<UText, E1, σ>')
    # ************************UDP服务器端编程*********************************
    v = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    v.bind(('127.0.0.1', 12347))  # 绑定端口

    # TXID_ST = b'8b60004928090023bef4292ed4e0e414a9f1eaa2d734d4b34beb5c6b2f33bb59'

    data_A3VI_UE, addr = v.recvfrom(4096)  # 接收A3VI返回的注册后的确认消息<TXID_UE, T_Exp>

    m_A3VI_UE = pickle.loads(data_A3VI_UE)
    TXID_ST = m_A3VI_UE['TXID_ST']
    # **********************UDP客户端编程【发送给EC消息进行认证】***************************************
    start_auth = time.clock()
    start_clo_auth = time.clock()
    SST = 0b10110001
    w = {'SST': SST, 'ID_A3VI': ID_A3VI}
    b_w = pickle.dumps(w)
    # 这里生成 Hidden_Alloewed_S_NSSAI
    k = hashlib.sha3_256()   #  这里利用sha256对密文进行哈希处理
    k.update(b_w)
    w_h = k.hexdigest()
    b_w_h = bytes(w_h, encoding='utf-8')   # 这里注意把 16进制的密文摘要转换为字节串，进行处理utf-8编码
    Hidden_Allowed_S_NSSAI = b_w_h

    # print('+++++++++++++++++++++++++++++++++++++++++++Inter-slice handover Authenticaion Phase++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    PID_UE = b'123456789abcdef12345'   # 用户自己随机选择一个20位的假名
    alpha = random.randint(1, order - 1)    # 用于计算变色龙哈希碰撞
    beta = random.randint(1, order - 1)
    Y = ChameleonHash.get_Y()

    A_UE = Y.pointQ.__mul__(alpha)  # A_UE = alpha * Y
    B_UE = Y.pointQ.__mul__(beta)   # B_UE = beta * Y

    T_Curr = time.clock()
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
    end_clo_auth = time.clock()
    end_auth = time.clock()
    print('UE端在服务认证阶段的计算开销为：', (end_auth-start_auth) * 1000, 'ms')
    print('UE端在服务认证阶段的计算开销(CPU时间)为：', (end_clo_auth-start_clo_auth) * 1000, 'ms')
    # # TXID_ST = b'8b60004928090023bef4292ed4e0e414a9f1eaa2d734d4b34beb5c6b2f33bb59'
    #
    # data_A3VI_UE, addr = v.recvfrom(4096)  # 接收A3VI返回的注册后的确认消息<TXID_UE, T_Exp>
    #
    # m_A3VI_UE = pickle.loads(data_A3VI_UE)
    # # print('007UE收到的注册确认消息TXID_UE：', m_A3VI_UE)
    # TXID_ST = m_A3VI_UE['TXID_ST']
    # end_reg = time.clock()
    # print('整个切片服务注册阶段计算开销为：', (end_reg-start_reg) * 1000, 'ms')


    data, addr = v.recvfrom(4096)
    m_UE_EC = {'Hidden_Allowed_S_NSSAI': Hidden_Allowed_S_NSSAI, 'PID_UE': PID_UE, 'A_UE': A_UE.xy, 'B_UE': B_UE.xy,
               'm_UE': m1, 'T_Curr': T_Curr, 'TXID_ST': TXID_ST}
    b_m_UE_EC = pickle.dumps(m_UE_EC)
    # print('+++1+++  UE >>>> EC 发送认证消息<Hidden_Allowed_S_NSSAI, PID_UE, A_UE, B_UE, m_UE, T_Curr, TXID_ST>')
    print('服务认证阶段消息<Hidden_Allowed_S_NSSAI, PID_UE, A_UE, B_UE, m_UE, T_Curr, TXID_ST>字节数：',
          len(Hidden_Allowed_S_NSSAI) +
          len(PID_UE) + 64 + 64 + m1.bit_length()/8 + T_Curr.__int__().bit_length()/8 + len(TXID_ST))
    if data == b'start':
        l = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        l.sendto(b_m_UE_EC, ('127.0.0.1', 12346))
        l.close()

    ack_data, addr = v.recvfrom(1024)
    DoKeyAgreement = pickle.loads(ack_data)
    if DoKeyAgreement:
        pass
        # print('***UE***收到密钥协商提示为True。')
    else:
        pass
        # print('***UE***收到密钥协商提示为False。')
    # end_auth =time.clock()
    # print('整个服务认证阶段计算开销为：', (end_auth - start_auth) * 1000, 'ms')

    # print('发送消息成功，消息内容为：', b_m_UE_EC)
    # 接收A3VI密钥协商材料，并计算协商材料K值
    agree_data, addr = v.recvfrom(4096)
    A3VI_UE = pickle.loads(agree_data)  # {'A_A3VI': A_A3VI, 'B_A3VI': B_A3VI}
    # print('***UE***接收到的A3VI的密钥协商材料为：', A3VI_UE)
    start_agree = time.clock()
    x_A = A3VI_UE['A_A3VI'][0]
    y_A = A3VI_UE['A_A3VI'][1]
    A_A3VI = ECC.EccPoint(x_A, y_A)
    x_B = A3VI_UE['B_A3VI'][0]
    y_B = A3VI_UE['B_A3VI'][1]
    B_A3VI = ECC.EccPoint(x_B, y_B)
    x_UE = ChameleonHash.get_x().__int__()
    K_UE = (A_A3VI + B_A3VI).__mul__(x_UE * (alpha + beta))
    # print('***UE***计算出的密钥协商材料K为：', K_UE.xy)
    # 开始计算协商密钥
    hash_m = [PID_UE, m1, K_UE.xy]
    # b_hash_m = pickle.dumps(hash_m)
    # print('哈希前的长度', len(b_hash_m))
    # h.update(b_hash_m[0:16])
    # SK_A3VI = h.hexdigest()
    # print(b_hash_m)
    b_hash_m = bytes_to_int(pickle.dumps(hash_m))
    SK_A3VI = hash(b_hash_m)
    end_agree = time.clock()
    print('UE端密钥协商阶段计算开销为：', (end_agree-start_agree)*1000, 'ms')
    # SK = hash(b_hash_m)
    # print('***UE***计算出的会话密钥[Int类型]为：', SK_A3VI)
    # print(SK)

    # 【通过EC】发送ACK_UE消息给A3VI
    hash_m1 = [K_UE.xy, SK_A3VI]
    ACK = hash(bytes_to_int(pickle.dumps(hash_m1)))
    b_ACK = pickle.dumps(ACK)
    s.sendto(b_ACK, ('127.0.0.1', 12345))
    s.close()
    # print('+++4+++ UE >>>> A3VI 发送消息ACK')
    print('密钥协商阶段消息<ACK>字节数为：', ACK.bit_length()/8)
    # print('++++++++++++++++++++UE端密钥协商完成！！！++++++++++++++++++++++++')

if __name__ == '__main__':
    print('Parent process start %s.')
    functions = [EC_func, A3VI_func, Ope_func, UE_func]
    manager = Manager()
    m_dict = manager.dict()
    processes = []
    for f in functions:
        p = Process(target=f,args=(m_dict,))
        p.start()
        processes.append(p)
    for p in processes:
        p.join()
    print(m_dict)

