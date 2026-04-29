# ChaCha20 stream cipher

This directory contains a few stream cipher from the ChaCha20 stream cipher famliy.

ChaCha20 is a variant of the Salsa20 stream cipher family used to encrypt and decrypt messages using a symmetric key. I have implemented the [ChaCha20 RFC 8439](https://en.wikipedia.org/wiki/Salsa20#Internet_standards) version, but without Poly1305 AEAD.

My implementation works the same as real life and is as secure as real life implementations of ChaCha20. However it lacks AEAD, this cipher is vulnerable to bit-flipping attacks as other stream ciphers.

If you want to know more about ChaCha20, you can look at the [official docs](https://cr.yp.to/chacha/chacha-20080128.pdf).
