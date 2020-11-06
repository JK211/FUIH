# FUIS Protocol Simulation

In this git, we implement a simulation to achieve our designed protocol FUIS, which is a Fast and Universal Inter-Slice Handover Authentication protocol. The detail message about 
the protocl can be viewed in our paper.

In this git, we basically make an intergrated protocol with chameleon hash funciton and ring signature under ECC. Besides, we still uses ECDSA signature and other hash function like
sha256.

Anyway, in this git, you can reproduce with your own IDE like pycharm or you can just use some useful cryptograhic primitives like Chameleon Hash Funciton, Ring Signature.

In the end, we declare two libraries called PyCryptodome3.9.8 and sslcrypto5.3 are principally used to implement cryptography primitives.

