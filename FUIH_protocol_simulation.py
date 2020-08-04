from multiprocessing import *
from EC import EC_func
from Ope import Ope_func
from UE import UE_func
from A3VI import A3VI_func
import time


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
