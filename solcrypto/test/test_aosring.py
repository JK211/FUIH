import unittest

from pysolcrypto.curve import randsn
from pysolcrypto.aosring import aosring_randkeys, aosring_check, aosring_sign
import time


class AosringTests(unittest.TestCase):
    def test_aos(self):
        msg = randsn()
        # msg = b'This is 225!'
        start0 = time.time()
        keys = aosring_randkeys(30)
        print('环成员生成时间：', (time.time() - start0) / 1000, 'ms')
        # print('环中的密钥以及签名者的密钥为：', keys)
        # print(type(keys))
        print('环中成员个数有：', len(keys[0]))
        print('环成员[公钥值]为：', keys[0])
        print('签名者[公钥+私钥]为：', keys[1])
        # self.assertTrue(aosring_check(*aosring_sign(*keys, message=msg), message=msg))
        print('----------------------------------------------------------------------------')
        start1 = time.time()
        RC = aosring_sign(*keys, message=msg)
        print('环签名为：', RC)
        print(type(RC))
        print('环签名验签时间：', (time.time() - start1) / 1000, 'ms')
        print()
        start2 = time.time()
        self.assertTrue(aosring_check(*RC, message=msg))
        print(aosring_check(*RC, message=msg))
        print('环签名验签时间：', (time.time()-start2) / 1000, 'ms')
        print('----------------------------------------------------------------------------')


if __name__ == "__main__":
    unittest.main()
