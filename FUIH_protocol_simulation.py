from multiprocessing import *
from EC import EC_func
from Ope import Ope_func
from UE import UE_func
from A3VI import A3VI_func
from results_data_record import excel_write


if __name__ == '__main__':

    file_name = r'D:\PythonProject\FUIH\simu_results_data\data_%s.xlsx'

    # usr_num = [85, 90, 95, 100] # 1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80,
    # usr_num = [1, 5, 10]
    usr_num =[5]
    for users in usr_num:
        openpyxl_data = []
        title = ('UE_Rge', 'Ope_Rge', 'A3VI_Rge', 'UE_Auth', 'EC_Auth', 'UE_KA', 'A3VI_KA', '1', '2', '3', '4', '5', '6', '7')
        openpyxl_data.append(title)
        for i in range(users):
            print('Parent process start %s.')
            functions = [EC_func, A3VI_func, Ope_func, UE_func]
            manager = Manager()
            m_dict = manager.dict()
            processes = []
            for f in functions:
                p = Process(target=f, args=(m_dict,))
                p.start()
                processes.append(p)
            for p in processes:
                p.join()
            print(m_dict)
            new_row = (m_dict['UE_Reg'], m_dict['Ope_Reg'], m_dict['A3VI_Reg'], m_dict['UE_Auth'], m_dict['EC_Auth'], m_dict['UE_KA'], m_dict['A3VI_KA'],
                       m_dict['1'], m_dict['2'], m_dict['3'], m_dict['4'], m_dict['5'], m_dict['6'], m_dict['7'])
            openpyxl_data.append(new_row)
        output_file_name = file_name % users
        excel_write.save_excel(openpyxl_data, output_file_name)
        print('数据写入data_%s.xlsx完毕！！！' % users)




