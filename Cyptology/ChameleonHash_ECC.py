#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.PublicKey import ECC
import random

"""
该变色龙哈希函数代码是基于ECC实现的，主要利用了开源的库Cryptodome，
我们定义了一个基点P，用户选择一个随机数x，使得Y=xP
对于输入（m,r），CH = mP + rY,  陷门信息可这样计算，k = m + r*x 陷门为 （k,x)
给定一个新的r1, 可计算m1 = k - r1*x 使得 CH1 = m1*P + r1*Y = CH 成立

作者： Jerry 
单位： XiDian University
时间： 2020/07/28
"""


# 一些关于ECC的基本参数
# P = ECC._curves['P-256'].G     # 这个是base point
# order_cint = ECC._curves['P-256'].order
# order = order_cint.__int__()   #  P点的阶数
# curve = ECC.generate(curve='P-256')  # 指定并生成椭圆曲线 P-256 = secp256r1


class CH(object):
    def __init__(self, CH, trapdoor):
        self.__CH = CH
        self.__trapdoor = trapdoor

    def CH(self):
        return self.__CH

    def trapdoor(self):
        return self.__trapdoor



class ChameleonHash(object):
    def __init__(self):
        self.__P = ECC._curves['P-256'].G  # 这个是base point
        # self.__P = P  # 这个是base point
        self.__order = ECC._curves['P-256'].order.__int__()  # P点的阶数 注意是int类型的
        # self.__order = order  # P点的阶数 注意是int类型的
        self.__curve = ECC.generate(curve='P-256')  # 指定并生成椭圆曲线 P-256 = secp256r1
        # self.__curve = curve  # 指定并生成椭圆曲线 P-256 = secp256r1


    def Compute_CH(self, m, r):  # 给定一个初始输入x,y 计算一个变色龙哈希函数值
        self.__Y = self.__curve.public_key()  # ECC公钥
        self.__x = self.__curve.d  # 这里表示用户选择的一个x  Y = xP
        self.__k = (m + r * self.__x.__int__()) % self.__order
        self.__CH = self.__Y.pointQ.__mul__(r) + self.__P.__mul__(m)

        return CH(CH=self.__CH.xy, trapdoor=(self.__k.__int__(), self.__x.__int__()))

    def order(self):
        return self.__order

    def get_Y(self):
        return self.__Y

    def get_P(self):
        return self.__P

    def get_x(self):
        return self.__x