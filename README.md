# Hash Length Extension for SHA1
## Theory of length extension attack

Imagine two people have shared a secret key and they want to sign their messages they send to each other with a hash algorithm. Every hash algorithm based on the construction of Merkle–Damgard is vulnarable to a attack which is called 'length extension attack' if the signature is computed by

    sig = hash(secret + message)

The purpose of this attack is to extend the original message and generate a new one which passes the signature check without knowing the shared secret. The idea is very simple:

Merkle-Damgard-algorithms operate on blocks of fixed size. If a message is longer the the block size, the message is splitted into blocks whichs fits the size. However, it's possible that the message length is not divisible by the block size without rest. That is one has to fill the last block up, so that it fits the block size. This is called padding.

A second thing you have to know is: After the result of a block is computed it is saved in internal registers, which are themselve needed to compute the hash, i.e. they have a new value after each block. Therefore, if the initial values of the registers differs, the result of the algorithm is another. The result of the hash algorithm is the value of the registers after the last block is computed.

So, if we know the original message and the original signature (which has to be sended as the other participant hash to check the integrity of the original message), we can pad the original message until our new message lies in a new block, concenate this with the new message and send this to the other participant. He sees:

    sig = hash(secret + message + padding + new_message)
                        |_____________________________|
                                 What we send

It is easy to generate the new valid signature as we know the value of the registers which is exactly their value after the message is computed until the end of the padding. Therefore we have to initialize our hash algorithm with the known signature of the original message and calculate with this the hash.

    new_sig = hash(new_message) <- with overriden registers

The only problem is: In a realistic case the attacker doesn't know the length of the secret but the padding differs for different lengths. So one has to go through all possibilities but this shouldn't be a problem. E.g. a script could be used to go through them.

It is possible to defend against the attack by using HMAC to generate the signature, meaning to generate the signature by

    sig = hash(secret + hash(secret + message))

The aim of this program is to implement this attack for the SHA1-algorithm. One hand over the original message, the new message, the signature of the original message and the secret length and get all information he needs to drive the attack.

## Example

     hash_extension -s secretfoo
     Signature: a5e702a34cc6d079645ff9634ac4b7c16ac41a68


     hash_extension -o foo -s bar -S a5e702a34cc6d079645ff9634ac4b7c16ac41a68 -k 6
     New Signature: 1acc2d421c1f1d209c919dfeef74ee94443b5afe

     What you probably wanna send to a server: 
     666f6f80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000048626172

     Or with characters: 
     foo80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000048bar

*Warning*: The implementation of SHA1 is not intended to be safe! Use proved and tested libraries for cryptography, only.

## Installation

Run:

   make
   make install

## License stuff

* License: MIT
* Copyright for commander.c/.h: Copyright (c) 2012 TJ Holowaychuk <tj@vision-media.ca>
* For the rest: Copyright (c) 2013 Karsten-Kai König <kkoenig@posteo.de>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
