from multiprocessing import *
from EC import EC_func
from Ope import Ope_func
from UE import UE_func
from A3VI import A3VI_func
import settings


if __name__ == '__main__':
    print('Parent process start %s.')
    last_pro = Process(target=A3VI_func)

    Process(target=EC_func).start()
    # Process(target=A3VI_func).start()
    last_pro.start()
    Process(target=Ope_func).start()
    Process(target=UE_func).start()
    settings.result_dict['last'] = 'end'
    last_pro.join()
    print(settings.result_dict)

    # Process(target=EC_func).start()
    # Process(target=A3VI_func).start()
    # Process(target=Ope_func).start()
    # Process(target=UE_func).start()
    #
    # settings.result_dict['last'] = 'end'
    # print(settings.result_dict)
