from multiprocessing import Pool
import os
import time


def run_EC(name):
    print('EC child process %s  ...' % name)
    os.system('python d:/PythonProject/FUIH/EC.py')
    # print(os.system('python d:/PythonProject/FUIH/EC.py'))
    print('111111')


def run_A3VI(name):
    print('A3VI child process %s ...' % name)
    os.system('python d:/PythonProject/FUIH/A3VI.py')
    # print(os.system('python d:/PythonProject/FUIH/A3VI.py'))
    print('222222')


def run_Ope(name):
    print('Operator child process %s ...' % name)
    os.system('python d:/PythonProject/FUIH/Ope.py')
    print('333333')

def run_UE(name):
    print('UE child process %s ...' % name)
    os.system('python d:/PythonProject/FUIH/UE.py')
    print('444444')

if __name__ == '__main__':
    print('Parent process start %s.')
    pool = Pool(6)
    pool.apply_async(run_EC, args=('EC',))
    pool.apply_async(run_A3VI, args=('A3VI',))
    pool.apply_async(run_Ope, args=('Ope',))
    pool.apply_async(run_UE, args=('UE',))

    pool.close()
    pool.join()
    print('All subprocesses done!')


    # print('Parent process.')
    # a = Process(target=run_EC('EC'), args=('test',))
    # a.start()
    # b = Process(target=run_A3VI('A3VI'), args=('test',))
    # b.start()
    # c = Process(target=run_Ope('Ope'), args=('test',))
    # c.start()
    # d = Process(target=run_UE('UE'), args=('test',))
    # d.start()



    # print('All processes done!!!!')
    # time.sleep(8)  #这里停留8秒等待上述进程交互结束
    # c.close()
    # b.close()
    # a.close()
    # d.close()
    # a.close()
    # b.close()
    # c.close()
    # d.close()
# print(os.system('python d:/PythonProject/FUIH/008.py'))
# print(os.system('start /b python d:/PythonProject/FUIH/EC.py'))
# print(os.system('start /b python d:/PythonProject/FUIH/A3VI.py'))
# print(os.system('start /b python d:/PythonProject/FUIH/Ope.py'))
# print(os.system('start /b python d:/PythonProject/FUIH/UE.py'))

# 后台运行，但需要改程序里的输出到一个文本文件中记录
# print(os.system('start /b python d:/PythonProject/FUIH/EC.py'))
# print(os.system('start /b python d:/PythonProject/FUIH/A3VI.py'))
# print(os.system('start /b python d:/PythonProject/FUIH/Ope.py'))
# print(os.system('start /b python d:/PythonProject/FUIH/UE.py'))

# print(a)

# if __name__ == "main":
#     a = os.system('python d:/PythonProject/FUIH/008.py')
#     print(a)
    # print(os.system('python D:/PythonProject/FUIH/EC.py'))
    # print(os.system('python D:/PythonProject/FUIH/A3VI.py'))
    # print(os.system('python D:/PythonProject/FUIH/Ope.py'))
    # print(os.system('python D:/PythonProject/FUIH/UE.py'))

# os.system(r'D:\PythonProject\FUIH\EC.py')
# os.system(r'D:\PythonProject\FUIH\A3VI.py')
# os.system(r'D:\PythonProject\FUIH\Ope.py')
# os.system(r'D:\PythonProject\FUIH\UE.py')
