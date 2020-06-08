/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.boniardi.testpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;

/**
 *
 * @author mboniardi
 */
public class PGPhelper {

    /**
     * On sending
     *
     * To encrypt request payload, to be the request body
     *
     * The PGP works as follow: First, creates a key to encrypt the payload,
     * then encrypts the key using the recipient's public key. Then encrypts the
     * payload using that key. Then signs the encrypted payload using the
     * sender's signature, so the recipient is sure that this is really from the
     * sender.
     *
     * @param sourceText, i.e. the payload string
     * @param pubKeyRing, sender's public key ring, containing also the
     * recipient's public key
     * @param privKeyRing, sender's private key ring
     * @param privKeyPwd, sender's private key password
     * @param sender, corresponds with user id in sender's key
     * @param recipient, corresponds with user id in recipient's key
     *
     * @return the encrypted message i.e. PGP message, must be set with UTF-8
     */
    String encryptWithKeys(String sourceText, String pubKeyString, String recipient)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        return encryptWithKeys(sourceText.getBytes(), pubKeyString, recipient);

    }

    /**
     * On sending
     *
     * To encrypt request payload, to be the request body
     *
     * The PGP works as follow: First, creates a key to encrypt the payload,
     * then encrypts the key using the recipient's public key. Then encrypts the
     * payload using that key. Then signs the encrypted payload using the
     * sender's signature, so the recipient is sure that this is really from the
     * sender.
     *
     * @param sourceText, i.e. the payload string
     * @param pubKeyRing, sender's public key ring, containing also the
     * recipient's public key
     * @param privKeyRing, sender's private key ring
     * @param privKeyPwd, sender's private key password
     * @param sender, corresponds with user id in sender's key
     * @param recipient, corresponds with user id in recipient's key
     *
     * @return the encrypted message i.e. PGP message, must be set with UTF-8
     */
    String encryptWithKeys(byte[] sourceBytes, String pubKeyString, String recipient)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        installBCProvider();

        KeyringConfig keyringConfig = keyringConfigInMemoryForKeys(pubKeyString);

        ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();

        OutputStream encryptionStream = BouncyGPG
                .encryptToStream()
                .withConfig(keyringConfig)
                .withStrongAlgorithms()
                .toRecipient(recipient)
                .andDoNotSign()
                .armorAsciiOutput()
                .andWriteTo(cipherStream);

        encryptionStream.write(sourceBytes);
        encryptionStream.close();
        cipherStream.close();

        byte[] cipherBytes = cipherStream.toByteArray();

        return new String(cipherBytes, Charset.forName("UTF-8"));
    }

    /**
     * On receiving
     *
     * To decrypt response body, to see the response payload
     *
     * The PGP works as follows: Decrypts the key (to open the payload) using
     * recipient's private key. It's possible because the key was encrypted
     * using the recipient's public key. Then, using that key, decrypts the
     * payload. Then, using the sender's signature, verifies if the payload is
     * really from the sender.
     *
     * @param cipherText, the PGP message to be decrypted
     * @param pubKeyRing, recipient's public key ring, containing also the
     * sender's public key
     * @param privKeyRing, recipient's private key ring
     * @param privKeyPwd, recipient's private key password
     * @param sender, corresponds with user id in sender's key
     *
     * @return the original text, must be set with UTF-8
     */
    String decryptAndVerify(String cipherText, File pubKeyRing, File privKeyRing, String privKeyPwd, String sender)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        installBCProvider();

        KeyringConfig keyringConfig = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPassword(privKeyPwd));

        //KeyringConfig keyringConfig = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
        //        privKeyRing, KeyringConfigCallbacks.withPassword(privKeyPwd));
        ByteArrayInputStream cipherStream = new ByteArrayInputStream(cipherText.getBytes());

        InputStream decryptedStream = BouncyGPG
                .decryptAndVerifyStream()
                .withConfig(keyringConfig)
                .andRequireSignatureFromAllKeys(sender)
                .fromEncryptedInputStream(cipherStream);

        byte[] decryptedBytes = Streams.readAll(decryptedStream);

        return new String(decryptedBytes, Charset.forName("UTF-8"));
    }

    /**
     * Call this before all PGP works, as we are using Jens Neuhalfen's library
     * based on Bouncy Castle
     */
    private void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static KeyringConfig keyringConfigInMemoryForKeys(final String exportedPubKey, final String exportedPrivateKey, String passphrase) throws IOException, PGPException {

        final InMemoryKeyring keyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPassword(passphrase));

        keyring.addPublicKey(exportedPubKey.getBytes("US-ASCII"));
        // you can add many more public keys

        keyring.addSecretKey(exportedPrivateKey.getBytes("US-ASCII"));
        // you can add many more privvate keys

        for (PGPPublicKeyRing key : keyring.getPublicKeyRings()) {
            for (Iterator iterator = key.getPublicKey().getUserIDs(); iterator.hasNext();) {
                String uid = (String) iterator.next();
                System.out.println("Public Uid: " + uid);
            }
        }

        for (PGPSecretKeyRing key : keyring.getSecretKeyRings()) {
            for (Iterator iterator = key.getSecretKey().getUserIDs(); iterator.hasNext();) {
                String uid = (String) iterator.next();
                System.out.println("Private Uid: " + uid);
            }
        }
        return keyring;
    }

    public static KeyringConfig keyringConfigInMemoryForKeys(final String exportedPubKey) throws IOException, PGPException {
        final InMemoryKeyring keyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
        keyring.addPublicKey(exportedPubKey.getBytes("US-ASCII"));
        // in case you can add many more public keys
        return keyring;
    }
   
    /**
     * 
     * @param protectionPassPhrase passphrase to protect keyRing or null to avoid passphraseProtection 
     * @return keyring created
     * @throws IOException
     * @throws PGPException 
     */
    public static KeyringConfig createKeyringInMemory(final String protectionPassPhrase) throws IOException, PGPException {
        InMemoryKeyring keyring = null;
        if (protectionPassPhrase != null) {
            keyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPassword(protectionPassPhrase));
        } else {
            keyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
        }
        return keyring;
    }
}
