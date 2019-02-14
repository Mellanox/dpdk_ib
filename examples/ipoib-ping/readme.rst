================================
IPoIB Ping example application
================================

Introduction
=============

The IPoIB ping application is an example of packet processing using the DPDK on top
of Infiniband link.

The application runs in a client-server mode. the client sends packets to the server
which receives them in an endless loop.

As part of the application boot, an Infiniband address exchange is performed between the client
and the server. After the exchange the application will init the DPDK eal layer and configure
the net PMD.

Prerequisite
=============

The application is built on support from the net PMD for IPoIB protocol and
manage the Infiniband link.

Before running the application make sure:
        * OS is RH7.3
        * MLNX_OFED_LINUX-4.1-0.0.4.0 is installed.
        * Opensm is running::

                opensm -B -g <port guid>

        * net device link is up::

                ifconfig <netdev> up

        * MTU is configured to the right value::

                ip link show <netdev>


Compiling the application
==========================

To compile the application:

1. Go to the sample application directory::

   export RTE_SDK=/path/to/rte_sdk
   cd ${RTE_SDK}/examples/ipoib-ping

2. Set the target (a default target is used if not specified). For example::

   export RTE_TARGET=x86_64-native-linuxapp-gcc

3. Build the application::

   make

Compiling the application
==========================

The application has a number of command line options depends on
the client/server mode selected::

        ./build/ipoib_ping [EAL options] -- --client -p SERVER_IP --checksums --debug
        ./build/ipoib_ping [EAL options] -- --server --debug

where,
        * -p SERVER_IP: Server IP address, requires for Infiniband address exchange.
        * --checksum: Sets the checksum Tx offload on the client side.
        * --debug: Sets debug logs verbosity.

.. raw:: pdf

   PageBreak

