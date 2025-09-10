# Second Price Auction (SPA) protocol
This is for the optimized implementation of the Second Price Auction (SPA) protocol.

The code is written in C++ and makes use of the OpenSSL library for the elliptic curve group operations and BIGNUM operations.

We implement a multiplicative group wrapper on top of the Elliptic curve group (which is essentially an additive group). Using these group operations, we implement Pedersen commitments, Uni-OT and the encoding scheme for our auction protocol. We also make use of SHA-256 hashing function from OpenSSL library.

The protocol requires use of a Bulletin Board which is simulated using Shared memory. For this, we make use of Boost Library.

The script bld can be used for building the sources.

Ample prints have been added to enable debugging. They can be enabled by compiling with option -DDEBUG. There are module specific debugs available for the encoding scheme used (-DENC-DEBUG) and group operations (-DGRP_DEBUG).

The script perf can be used for running the auction. The perf script can be configured for choosing suitable number of bidders and their bid values. 

We have chosen static instantiation of the shared memory. Thus, for any changes to configure the number of bidders or bit length of the bid, we change in the common.h file and recompile.

# spa_new
