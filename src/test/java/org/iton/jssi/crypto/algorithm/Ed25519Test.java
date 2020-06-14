/*
 *
 *  The MIT License
 *
 *  Copyright 2019 ITON Solutions.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

package org.iton.jssi.crypto.algorithm;

import org.bitcoinj.core.Base58;
import org.bouncycastle.util.Arrays;
import org.iton.jssi.crypto.CryptoException;
import org.iton.jssi.crypto.Keys;
import org.iton.jssi.crypto.util.Utils;
import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

class Ed25519Test {

    private static final Logger LOG = LoggerFactory.getLogger(Ed25519.class);
    public Ed25519Test() {
        NaCl.sodium();
    }


    @Test
    void testCreateKeys() throws SodiumException {
        Ed25519 instance = new Ed25519();
        Keys keys = instance.createKeys(Utils.toBytes("0000000000000000000000000000000000000000000000000000000000000000"));
        assertArrayEquals(Base58.decode(keys.verkey), Utils.toBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"));
    }

    @Test
    void testSign() throws SodiumException, CryptoException {
        byte[] data = "This is a secret message".getBytes();
        Ed25519 instance = new Ed25519();
        Keys keys = instance.createKeys(Utils.toBytes("0000000000000000000000000000000000000000000000000000000000000000"));
        byte[] cipher = instance.sign(data, Base58.decode(keys.signkey));
        // cipher = sign + msg
        byte[] sign = Arrays.copyOfRange(cipher, 0, cipher.length - data.length);
        byte[] msg = Arrays.copyOfRange(cipher, cipher.length - data.length, cipher.length);
        byte[] expected = Utils.toBytes("94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");
        assertArrayEquals(expected, sign);
        assertArrayEquals(msg, data);
    }

    @Test
    void testVerifySeedNull() throws SodiumException, CryptoException {
        byte[] data = "Hola caracola".getBytes();
        Ed25519 instance = new Ed25519();
        Keys keys = instance.createKeys(null);
        byte[] sign = instance.sign(data, Base58.decode(keys.signkey));
        boolean result = instance.verify(data, sign, Base58.decode(keys.verkey));
        assertTrue(result);
    }

    @Test
    void testVerifyKeys() throws SodiumException, CryptoException {
        byte[] data = "Hola caracola".getBytes();
        Ed25519 instance = new Ed25519();
        Keys keys = new Keys("8Uw8tTr5u9GQPXHBWxwdpurYFGDtkwLcYiGX3pMfaCRC", "542Gch9kfaUrQsFmfYdFnPBnZtcfvCuptvX64DpSuae4sbydr7KCGn4cKJdEgPtbNGTAfEsZv8kqdDWPoZQDUpJ2");
        byte[] sign = instance.sign(data, Base58.decode(keys.signkey));
        boolean result = instance.verify(data, sign, Base58.decode(keys.verkey));
        assertTrue(result);
    }

    @Test
    void testVerifySeedNotNull() throws SodiumException, CryptoException {
        byte[] data = "Hola caracola".getBytes();
        Ed25519 instance = new Ed25519();
        Keys keys = instance.createKeys("00000000000000000000000000000My1".getBytes());
        byte[] sign = instance.sign(data, Base58.decode(keys.signkey));
        boolean result = instance.verify(data, sign, Base58.decode(keys.verkey));
        assertTrue(result);
    }

    @Test
    void testGenNonce() {
    }

    @Test
    void testCryptoBox() throws SodiumException {
        byte[] data = "Hola caracola".getBytes();
        Ed25519 instance = new Ed25519();
        Keys sender = instance.createKeys(null);
        Keys receiver = instance.createKeys(null);
        byte[] nonce = instance.genNonce();
        byte[] cipher = instance.cryptoBox(data, nonce, Base58.decode(receiver.verkey), Base58.decode(sender.signkey));
        assertNotNull(cipher);
    }

    @Test
    void testCryptoBoxOpen() throws SodiumException {
        byte[] data = "Hola caracola".getBytes();
        Ed25519 instance = new Ed25519();
        Keys sender = instance.createKeys(null);
        Keys receiver = instance.createKeys(null);
        byte[] nonce = instance.genNonce();
        byte[] cipher = instance.cryptoBox(data, nonce, Base58.decode(receiver.verkey), Base58.decode(sender.signkey));
        byte[] result = instance.cryptoBoxOpen(cipher, nonce, Base58.decode(sender.verkey), Base58.decode(receiver.signkey));
        assertArrayEquals(data, result);
    }

    @Test
    void testCryptoBoxOpenKeys() throws SodiumException {
        byte[] data = "Hola caracola".getBytes();
        Ed25519 instance = new Ed25519();
        Keys sender = new Keys("8Uw8tTr5u9GQPXHBWxwdpurYFGDtkwLcYiGX3pMfaCRC", "542Gch9kfaUrQsFmfYdFnPBnZtcfvCuptvX64DpSuae4sbydr7KCGn4cKJdEgPtbNGTAfEsZv8kqdDWPoZQDUpJ2");
        Keys receiver = new Keys("EUc5i7EW7XZkxcXhvnoZu9ipFdZ91LD8C75rVoAgKdRd", "5nVf7MnrmakrMLkhsbLFmVhVWabwyxeh64qR5um9L4pHCqnjsj7JrHGfMMHpNPyN2LFVsX5HD1wLxW7E7jMNzEgb");
        byte[] nonce = instance.genNonce();
        byte[] cipher = instance.cryptoBox(data, nonce, Base58.decode(receiver.verkey), Base58.decode(sender.signkey));
        byte[] result = instance.cryptoBoxOpen(cipher, nonce, Base58.decode(sender.verkey), Base58.decode(receiver.signkey));
        assertArrayEquals(data, result);
    }

    @Test
    void cryptoBoxSeal() {
    }

    @Test
    void testCryptoBoxSealOpen() throws SodiumException {
        byte[] data = "Hola caracola".getBytes();
        Ed25519 instance = new Ed25519();
        Keys keys = instance.createKeys(null);
        byte[] cipher = instance.cryptoBoxSeal(data, Base58.decode(keys.verkey));
        byte[] result = instance.cryptoBoxSealOpen(cipher, Base58.decode(keys.verkey), Base58.decode(keys.signkey));
        assertArrayEquals(data, result);

    }

    @Test
    void getType() {
    }

    @Test
    void testValidateKey() {
    }
}