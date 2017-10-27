# QUASIKOM

The [Internet of Things (IoT)](http://en.wikipedia.org/wiki/Internet_of_things
"Internet of things on Wikipedia") refers to the vision of a global network of
physical objects (i.e. "things") equipped with computing and wireless
communication capabilities that enable them to be uniquely identified or even
exchange data with other connected devices. RFID tags and wireless sensor nodes
constitute the first wave of such non-traditional computing devices that will
soon populate the Internet ecosystem in vast quantities. An ever-increasing
number of everyday objects, ranging from kitchen appliances over items of
clothing and sports goods to cars and other vehicles, become equipped with
microprocessors and wireless transceivers, which enables them to communicate
with each other and access central resources over the Internet. In a recent
white paper, Cisco estimates the number of smart objects connected to the
Internet to exceed [50
billion](http://www.cisco.com/c/dam/en_us/about/ac79/docs/innov/IoT_IBSG_0411FINAL.pdf
"Cisco IoT white paper") in 2020. This evolution of the Internet will change
the way how we interact with the physical world surrounding us and create
exciting new opportunities for the economy in such areas as health care,
industrial automation, resource management, and transportation and logistics,
to name a few.

The advent of [quantum
computing](http://en.wikipedia.org/wiki/Quantum_computing "Quantum computing on
Wikipedia") is another technological revolution that will soon have a profound
impact on our daily life and may even disrupt whole industries. In the not so
distant future, quantum computers will be powerful enough to aid the discovery
of new drugs or materials, to organize the routes of millions of self-driving
cars in metropolitan areas without introducing traffic jams, or to manage and
improve the efficiency of national power grids. Unfortunately, quantum
computing has also a destructive side because a large-scale quantum computer
would be able to break essentially every public-key cryptosystem in use today,
in particular RSA and ECC. However, there exist a few public-key cryptographic
algorithms that are unbreakable not only for classical computers, but also when
using a sophisticated quantum computer. The sub-area of cryptography that deals
with the design, cryptanalysis, and implementation of cryptographic algorithms
supposed to be able to withstand attacks by quantum computers is known as
[Post-Quantum Cryptography
(PQC)](http://en.wikipedia.org/wiki/Post-quantum_cryptography "Post-quantum
cryptography on Wikipedia") and has recently gained a lot of interest,
especially after the NIST announced an [initiative to
standardize](http://csrc.nist.gov/Projects/Post-Quantum-Cryptography "NIST
post-quantum cryptography project") quantum-safe cryptographic algorithms.

The project QUASIKOM ("Post-Quantum Secure Communication for the Internet of
Things") lies thematically at the intersection of these two technological
revolutions and aims to make the IoT resistant against cryptanalytic attacks
with a quantum computer. More concretely, the goal of QUASIKOM is to develop a
post-quantum secure version of the [Datagram Transport Layer Security
(DTLS)](http://tools.ietf.org/html/rfc6347 "RFC6347") protocol, which is the
de-facto standard for end-to-end authentication and encryption in the IoT. It
is also planned to implement a prototype of such a "hardened" DTLS protocol,
whereby the open-source software
[TinyDTLS](http://sourceforge.net/projects/tinydtls "TinyDTLS home page") will
be used as a starting point. TinyDTLS is aimed at resource-constrained IoT
devices equipped with an 8, 16, or 32-bit microcontroller that is clocked with
a frequency of a few MHz. The main task of the project is to implement an
NTRU-based key establishment mechanism and its integration into TinyDTLS to
replace the currently used RSA-based key transport and Diffie-Hellman key
exchange, which can both be broken with a quantum computer.
[NTRU](http://www.onboardsecurity.com/products/ntru-crypto "NTRU home page") is
a well-studied lattice-based cryptosystem that combines high computational
efficiency with relatively short key lengths, which makes it well suited for
the IoT. To date (as of October 2017), the performance-critical arithmetic
operations NTRU already exist in both C and Assembly language.

 The QUASIKOM project is supported by
[Netidee](http://www.netidee.at "NetIdee Homepage").
