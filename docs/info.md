<!---

This file is used to generate your project datasheet. Please fill in the information below and delete any unused
sections.

You can also include images in this folder and reference them in the markdown. Each image must be less than
512 kb in size, and the combined size of all images must be less than 1 MB.
-->

## How it works

This project implements an AES-128 encryption core with a Tiny Tapeout-compatible byte-serial wrapper.

The internal AES core encrypts one 128-bit plaintext block using one 128-bit key and produces one 128-bit ciphertext block. Because Tiny Tapeout only provides 8-bit input and output buses, the wrapper loads the key and plaintext one byte at a time.

The wrapper uses `ui_in[7:0]` as the input data byte. The `uio_in` pins select whether the byte belongs to the key or plaintext, choose the byte index, and issue control commands. After all 16 key bytes are written, `load_key_cmd` is pulsed to start AES key expansion. After all 16 plaintext bytes are written, `start_encrypt_cmd` is pulsed to start encryption.

The AES core then performs AES-128 encryption using the stored key and plaintext. When the ciphertext is ready, the wrapper latches the 128-bit ciphertext internally. The user can then read the ciphertext one byte at a time through `uo_out[7:0]` by selecting the desired byte index using `uio_in[3:0]`.

The design is based on a pipelined AES datapath. The AES core uses a ROM-style S-box implementation and a valid-signal pipeline to indicate when the ciphertext output is valid.


## How to test

The project can be tested by loading a known AES-128 test vector through the Tiny Tapeout pins.

Example test vector:

- Key: `000102030405060708090a0b0c0d0e0f`
- Plaintext: `00112233445566778899aabbccddeeff`
- Expected ciphertext: `69c4e0d86a7b0430d8cdb78070b4c55a`


## External hardware

List external hardware used in your project (e.g. PMOD, LED display, etc), if any
