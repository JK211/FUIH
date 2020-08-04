from multiprocessing import *
import set
from test1 import run_test1
from test2 import run_test2
from test3 import run_test3

if __name__ == '__main__':
    print('Parent process start %s.')

    Process(target=run_test1()).start()
    Process(target=run_test2()).start()
    Process(target=run_test3()).start()

    set.result_dict['test4'] = 'test4'
    print(set.result_dict)
