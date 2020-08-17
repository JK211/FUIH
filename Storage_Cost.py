#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
这个模块用于计算EC和AUSF的存储开销，并记录到excel方便绘图

2020/8/9
Jerry
"""
from results_data_record import excel_write

l = []
title = ['Data_EC', 'Data_AUSF']
l.append(title)
for i in range(1, 12):
    m = []
    EC_i = (80*(630000+52560*i)+69*7600000000*pow(1+0.11, i))/(1024*1024*1024)      #  GB
    AUSF_i = (80*(630000+52560*i)+95*7600000000*pow(1+0.11, i))/(1024*1024*1024)
    m.append(EC_i)
    m.append(AUSF_i)
    l.append(m)

file_name = r'D:\PythonProject\FUIH\simu_results_data\Storage_Cost.xlsx'
excel_write.save_excel(l, file_name)
