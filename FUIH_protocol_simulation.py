from multiprocessing import *
import os
import time
from EC import EC_func
from Ope import Ope_func
from UE import UE_func
from A3VI import A3VI_func
import settings


if __name__ == '__main__':
    print('Parent process start %s.')
    Process(target=EC_func).start()
    Process(target=A3VI_func).start()
    Process(target=Ope_func).start()
    Process(target=UE_func).start()
    print(settings.result_dict)
