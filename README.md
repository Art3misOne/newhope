# New Hope Key Exchange and Key Encapsulation

This repo consists of a java implementation of New-Hope and New-Hope-Simple.

  - "Post Quantum Key Exchange - a New Hope" by Erdem Alkim, Leo Ducas, Thomas Poppelmann, and
    Peter Schwabe. https://eprint.iacr.org/2015/1092.
  - "NewHope without reconciliation" by Erdem Alkim, Leo Ducas, Thomas Poppelmann, and
    Peter Schwabe. https://eprint.iacr.org/2016/1157.
  - https://newhopecrypto.org 

The first paper published an algorithm called "New Hope" using a complex reconciliation method to 
reach a shared key agreement. The same authors later released another paper discussing how to replace 
the complex reconciliation method with a much simpler mechanism to encode/decode a chosen key. The 
new version was called New Hope Simple.

The New Hope Simple algorithm was submitted to the NIST competition under the name New Hope. Please
see the third link above for the latest status and information on the New Hope algorithm(s). Although 
the original version with reconciliation appears to have been subsumed by the newer version without, 
this repository includes both for completeness. The original version with reconciliation is instantiated 
through the NewHopeKeyExchange object and the newer version without reconciliation is instantiated 
through the NewHopeKem object.

Various open source implementations use different NTT implementations for computing fast polynomial
multiplication. This implementation uses the Longa/Naehrig NTT optimizations:

  - "Speeding up the Number Theoretic Transform for Faster Ideal Lattice-Based Cryptography" by
    Patrick Longa and Michael Naehrig. https://eprint.iacr.org/2016/504.

An additional parameter is included to support regression testing and facilitate interoperability
between implementations using different NTT implementations. Keys can be transmitted in the ordinary
domain (for interoperability) or the Fourier domain (for greater efficiency). By default, keys are
transmitted in the Fourier domain.

This code is designed to be compatible with the Signal framework and style guide:

  - https://github.com/signalapp/Signal-Android
