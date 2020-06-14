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

package org.iton.jssi.crypto;

import org.iton.jssi.did.Did;
import org.iton.jssi.did.MyDidInfo;
import org.iton.jssi.did.TheirDid;
import org.iton.jssi.did.TheirDidInfo;
import org.iton.jssi.util.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {

    public CryptoServiceTest(){
        NaCl.sodium();
    }

    @BeforeEach
    void setUp() {
    }

    @Test
    void createKey() {
    }

    @Test
    void testCreateMyDidInfoNull() throws SodiumException {
        CryptoService instance = new CryptoService();
        Pair<Did, Keys> result = instance.createMyDid(new MyDidInfo(null, null));
        assertNotNull(result);

    }

    /**
     * Test of testCreate_their_did_null method, of class CryptoService.
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testCreateTheirDidNull() throws CryptoException {
        CryptoService instance = new CryptoService();

        TheirDid result = instance.createTheirDid(new TheirDidInfo("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW", null));
        assertEquals(result.did, "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW");
        assertEquals(result.verkey, "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW");
    }

    /**
     * Test of testCreate_their_did method, of class CryptoService.
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testCreateTheirDid() throws CryptoException {
        CryptoService instance = new CryptoService();
        String did = "8wZcEriaNLNKtteJvx7f8i";
        String verkey = "5L2HBnzbu6Auh2pkDRbFt5f4prvgE2LzknkuYLsKkacp";
        TheirDidInfo info = new TheirDidInfo(did, verkey);
        TheirDid result = instance.createTheirDid(info);
        assertEquals(result.did, did);
        assertEquals(result.verkey, verkey);
    }

    /**
     * Test of testCreate_their_did_abbreviated method, of class CryptoService.
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testCreateTheirDidAbbreviated() throws CryptoException {
        CryptoService instance = new CryptoService();
        String did = "8wZcEriaNLNKtteJvx7f8i";
        String verkey = "~NcYxiDXkpYi6ov5FcYDi1e";
        TheirDidInfo info = new TheirDidInfo(did, verkey);
        TheirDid result = instance.createTheirDid(info);
        assertEquals(result.did, did);
        assertEquals(result.verkey, "5L2HBnzbu6Auh2pkDRbFt5f4prvgE2LzknkuYLsKkacp");
    }


    /**
     * Test of createMyDid method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     */
    @Test
    public void testCreateMyDid() throws SodiumException {
        CryptoService instance = new CryptoService();
        Pair<Did, Keys> result = instance.createMyDid(new MyDidInfo("NcYxiDXkpYi6ov5FcYDi1e", null));
        assertEquals(result.first.did, "NcYxiDXkpYi6ov5FcYDi1e");
    }

    /**
     * Test of createMyDid method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     */
    @Test
    public void testCreateMyDidSeed() throws SodiumException {
        CryptoService instance = new CryptoService();
        MyDidInfo did_info_with_seed = new MyDidInfo("NcYxiDXkpYi6ov5FcYDi1e", "00000000000000000000000000000My1");
        MyDidInfo did_info_without_seed = new MyDidInfo("NcYxiDXkpYi6ov5FcYDi1e", null);

        Pair<Did, Keys> did_with_seed = instance.createMyDid(did_info_with_seed);
        Pair<Did, Keys> did_without_seed = instance.createMyDid(did_info_without_seed);

        assertNotEquals(did_with_seed.second.verkey, did_without_seed.second.verkey);
    }

    /**
     * Test of sign method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testSign() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        byte[] result = instance.sign(data, keys);
        assertNotNull(result);
    }

    /**
     * Test of sign method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testSignInvalidSk() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();
        // signkey must be 64 bytes long
        CryptoService instance = new CryptoService();
        Keys keys = new Keys("8wZcEriaNLNKtteJvx7f8i", "5L2HBnzbu6Auh2pkDRbFt5f4prvgE2LzknkuYLsKkacp");
        Assertions.assertThrows(CryptoException.class, () -> {
            instance.sign(data, keys);
        });
    }

    /**
     * Test of verify method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testVerify() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        byte[] sign = instance.sign(data, keys);
        boolean result = instance.verify(data, sign, keys);
        assertTrue(result);
    }

    /**
     * Test of verify method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testVerifyCryptoType() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        byte[] sign = instance.sign(data, keys);
        boolean result = instance.verify(data, sign, keys);
        assertTrue(result);
    }

    /**
     * Test of verify method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testVerifyInvalidPk() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        byte[] sign = instance.sign(data, keys);
        keys.verkey = "AnnxV4t3LUHKZaxVQDWoVaG44NrGmeDYMA4Gz6C2tCZd";
        Assertions.assertThrows(SodiumException.class, () -> {
            instance.verify(data, sign, keys);
        });
    }

    /**
     * Test of crypto_box method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testCryptoBox() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys sender = instance.createKeys(null);
        Keys receiver = instance.createKeys(null);
        CryptoBox result = instance.cryptoBox(data, sender, receiver);
        assertNotNull(result);
    }

    /**
     * Test of cryptoBoxOpen method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testCrypto_box_open() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys sender = instance.createKeys(null);
        Keys receiver = instance.createKeys(null);
        CryptoBox box = instance.cryptoBox(data, sender, receiver);
        byte[] result = instance.cryptoBoxOpen(box.cipher, box.nonce, receiver, sender);
        assertArrayEquals(result, data);
    }

    /**
     * Test of cryptoBox method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testCryptoBoxOpenWithType() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys sender = instance.createKeys(null);
        Keys receiver = instance.createKeys(null);
        CryptoBox box = instance.cryptoBox(data, sender, receiver);
        byte[] result = instance.cryptoBoxOpen(box.cipher, box.nonce, sender, receiver);
        assertArrayEquals(result, data);
    }

    @Test
    public void testCryptoBoxOpenWithErrorType() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys sender = instance.createKeys(null);
        Keys receiver = instance.createKeys(null);
        CryptoBox box = instance.cryptoBox(data, sender, receiver);
        receiver.verkey = receiver.verkey.split(":")[0] + ":bad tipe";
        Assertions.assertThrows(CryptoException.class, () -> {
            byte[] result = instance.cryptoBoxOpen(box.cipher, box.nonce, receiver, sender);
        });
    }

    /**
     * Test of cryptoBoxSeal method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testCryptoBoxSeal() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        byte[] result = instance.cryptoBoxSeal(keys, data);
        assertNotNull(result);
    }

    /**
     * Test of cryptoBoxSealOpen method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testCryptoBoxSealOpen() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        byte[] cipher = instance.cryptoBoxSeal(keys, data);
        byte[] result = instance.cryptoBoxSealOpen(keys, cipher);
        assertArrayEquals(result, data);
    }

    /**
     * Test of encrypt_plaintext method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testEncryptDecryptPlaintext() throws SodiumException, CryptoException {

        byte[] data = "Hola caracola".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        CryptoDetached result = instance.encryptPlaintext(data, add, keys);
        String message = instance.decryptPlaintext(result, add, keys);
        assertEquals(message, "Hola caracola");
    }

    /**
     * Test of encrypt_plaintext method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testEncryptDecryptPlaintextNull() throws SodiumException, CryptoException {

        byte[] data = "".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        CryptoDetached result = instance.encryptPlaintext(data, add, keys);
        String message = instance.decryptPlaintext(result, add, keys);
        assertEquals(message, "");
    }

    /**
     * Test of testEncrypt_decrypt_plaintext_bad_nonce method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testEncrypt_decrypt_plaintext_bad_nonce() throws SodiumException, CryptoException {

        byte[] data = "".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        CryptoDetached result = instance.encryptPlaintext(data, add, keys);
        result.nonce = Base64.getEncoder().encodeToString("bad nonce".getBytes());
        Assertions.assertThrows(SodiumException.class, () -> {
            instance.decryptPlaintext(result, add, keys);
        });
    }

    /**
     * Test of testEncrypt_decrypt_plaintext_bad_cipher method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testEncryptDecryptPlaintextBadCipher() throws SodiumException, CryptoException {

        byte[] data = "".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        CryptoDetached result = instance.encryptPlaintext(data, add, keys);
        result.cipher = Base64.getEncoder().encodeToString("bad cipher".getBytes());

        Assertions.assertThrows(SodiumException.class, () -> {
            instance.decryptPlaintext(result, add, keys);
        });
    }

    /**
     * Test of testEncrypt_decrypt_plaintext_bad_key method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testEncryptDecryptPlaintextBadKey() throws SodiumException, CryptoException {

        byte[] data = "".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        CryptoDetached result = instance.encryptPlaintext(data, add, keys);
        Keys keys1 = instance.createKeys(null);
        String message = instance.decryptPlaintext(result, add, keys);
        Assertions.assertThrows(SodiumException.class, new Executable() {
            @Override
            public void execute() throws Throwable {
                instance.decryptPlaintext(result, add, keys1);
            }
        });
    }

    /**
     * Test of testEncrypt_decrypt_plaintext_bad_tag method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testEncryptDecryptPlaintextBadTag() throws SodiumException, CryptoException {

        byte[] data = "".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        CryptoDetached result = instance.encryptPlaintext(data, add, keys);
        result.tag = Base64.getEncoder().encodeToString("bad tag".getBytes());
        Assertions.assertThrows(SodiumException.class, () -> {
            instance.decryptPlaintext(result, add, keys);
        });
    }

    /**
     * Test of testEncrypt_decrypt_plaintext_bad_add method, of class CryptoService.
     * @throws org.libsodium.jni.SodiumException
     * @throws org.iton.jssi.crypto.CryptoException
     */
    @Test
    public void testEncryptDecryptPlaintextBadAdd() throws SodiumException, CryptoException {

        byte[] data = "".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();

        CryptoService instance = new CryptoService();
        Keys keys = instance.createKeys(null);
        CryptoDetached result = instance.encryptPlaintext(data, add, keys);
        byte[] add1 = "bad add".getBytes();
        Assertions.assertThrows(SodiumException.class, () -> {
            instance.decryptPlaintext(result, add1, keys);
        });
    }
}