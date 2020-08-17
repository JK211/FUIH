#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import openpyxl

"""
该模块用于把simulation过程中记录的数据写进excel
方便数据进行后续的分析和计算

作者： Jerry 
单位： 
时间： 2020/08/04
"""


def save_excel(target_list, output_file_name):
    """
    将数据写入xlsx文件
    :param target_list:
    :param out_file_name:
    :return:
    """
    if not output_file_name.endswith('.xlsx'):
        output_file_name += '.xlsx'

    # 创建一个workbook对象
    wb = openpyxl.Workbook()
    # 获取当前活跃的worksheet
    ws = wb.active
    # title_data = ('a', 'b', 'c', 'd', 'e', 'f', 'g', 'i', 'j', 'k', 'm', 'l', 'n', 'o')
    # target_list.insert(0, title_data)
    rows = len(target_list)
    lines = len(target_list[0])
    for i in range(rows):
        for j in range(lines):
            ws.cell(row=i+1, column=j+1).value = target_list[i][j]

    wb.save(filename=output_file_name)