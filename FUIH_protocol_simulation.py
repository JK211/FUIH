from multiprocessing import *
import os
import time
from EC import EC_func
from Ope import Ope_func
from UE import UE_func
from A3VI import A3VI_func
from results_record.global_dict import gol


if __name__ == '__main__':

    print('Parent process start %s.')

    end = Process(target=A3VI_func)

    Process(target=EC_func).start()
    # Process(target=A3VI_func).start()
    end.start()
    Process(target=Ope_func).start()
    Process(target=UE_func).start()

    end.join()
    print(gol.get_value('UE_Rge'))
    print(gol.get_value('Ope_Rge'))
    print(gol.get_value('A3VI_Rge'))










