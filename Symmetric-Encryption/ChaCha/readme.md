# ChaCha20 stream cipher

This directory contains a few stream cipher from the ChaCha20 stream cipher famliy.

ChaCha20 is a variant of the Salsa20 stream cipher family used to encrypt and decrypt messages using a symmetric key. I have implemented the [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#XChaCha) version, but without Poly1305 AEAD.

Claude implemented the full AEAD cipher XChaCha20-Poly1305.

My implementation(XChaCha20.ms) works the same as real life and is as secure as real life implementations of XChaCha20. However it lacks AEAD, this cipher is vulnerable to bit-flipping attacks as other stream ciphers. XChaCha-Poly1305(XChaCha20_Poly1305.ms) is immune to such attack, however it was implemented by Claude and has not been audited.

If you want to know more about ChaCha20, you can look at the [official docs](https://cr.yp.to/chacha/chacha-20080128.pdf).
