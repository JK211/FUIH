# FUIS Protocol Simulation

In this git, we implement a simulation to achieve our designed protocol FUIS, which is a Fast and Universal Inter-Slice Handover Authentication protocol. The detail message about 
the protocol can be viewed in our paper.

In this git, we basically make an intergrated protocol with chameleon hash funciton and ring signature under ECC. Besides, we still uses ECDSA signature and other hash function like sha256. We also provide some simulation results in this git for futher reference to any researchers who interested in our work.

Anyway, in this git, you can reproduce our work with your own IDE like pycharm or you can just use some useful cryptograhic primitives like Chameleon Hash Funciton, Ring Signature under the file Cyptology.

In the end, we declare two libraries called PyCryptodome3.9.8 and sslcrypto5.3 are principally used to implement cryptography primitives. Because the time is too tight and the code level of author is limited, we are sorry about the poor code qulity. And we welcome everyone to improve this git.

