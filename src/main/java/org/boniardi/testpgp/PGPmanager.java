/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.boniardi.testpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;

/**
 *
 * @author mboniardi
 */
public class PGPmanager {

    private String internalPassPhrase = "";
    private InMemoryKeyring keyring = null;

    /**
     * All init procedure inside creator
     */
    PGPmanager() {
        try {
            // you can pass the pwd to protect the private Key
            keyring = createKeyringInMemory(null);
            //load keys from ... configuration
            loadKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @param email
     * @param sourceString
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws SignatureException
     */
    public String encrypt(String email, String sourceString)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, Exception {
        return encrypt(email, sourceString.getBytes());
    }

    /**
     *
     * @param email
     * @param sourceBytes
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws SignatureException
     */
    public String encrypt(String email, byte[] sourceBytes)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, Exception {
        installBCProvider();
        ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();
        String recipient = getUserIDfromEmail(email, false);
        System.out.println("----" + recipient);

        OutputStream encryptionStream = BouncyGPG
                .encryptToStream()
                .withConfig(keyring)
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
    String decrypt(String cipherText)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        installBCProvider();

        ByteArrayInputStream cipherStream = new ByteArrayInputStream(cipherText.getBytes());

        InputStream decryptedStream = BouncyGPG
                .decryptAndVerifyStream()
                .withConfig(keyring)
                .andIgnoreSignatures()
                .fromEncryptedInputStream(cipherStream);

        byte[] decryptedBytes = Streams.readAll(decryptedStream);

        return new String(decryptedBytes, Charset.forName("UTF-8"));
    }

    private void loadKeys() throws Exception {
        // to rewrite with upload from Configutation
        String email = "test@test.org";
        String privkeyString = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
                + "\n"
                + "xcaGBF7f8NsBEACt75Hr0m4Tvrqht/WwwnAnplP8LMY45y743NMW5VAtmgM/\n"
                + "N0GyTJFG+Gt1THEhQVSVXCyhx837DFUj7dToEH7+2cJzaUcFphtBlFPc3Qpr\n"
                + "nCH2uIW2wYW3+Mr27oLZ5SYVCbErN6OCG4bcYyDlKY1zay2iQmnPaoEBf/CI\n"
                + "V092HTtqb8w7ABhRpDGfKQNy+/DNsJcxbgGlwrnftEpfaPmpAvXCG9bv34yD\n"
                + "3eKGmG5rhFbplqFd89cYw214JFW8f/tTNp2xCSYdZiBsbUcXdeoMAYiz4Bhl\n"
                + "q0KbHHf8IWEZc/vMjefoV9bb9XW0DsnRNZs4ukg3q7ta+qngFd/DfbHutUQR\n"
                + "Q0Z9oiUS0A7l5stlwppLyTYQCv8O58FUerVAxqJKHiB47G2hq7RSbi/7M2hD\n"
                + "xdI5Fn37HvfZ8Rv617YTlUIZNE9QkoQtyBm48GRNT89r9rncNCggfY4aH9Z7\n"
                + "Me5/rfOyhosDyhH5G858F4IzeJbrPzoZWux7aYSdl33X/Jlz830nTmbS5cgm\n"
                + "0n/SySRqErxI2g1JLuit2lf5//ANI6EaKpI8xJAk/pX+xHHzhXvAoIJl4qe4\n"
                + "Mgv17xz9J4NUuQtMRhlyJPnFe9exZ06h7/qCu5tpzDY5o258RD55zmclKgSP\n"
                + "9A5YejI1/cJHAHFJgXnJFNTRS1ITguWcAkbrKwARAQAB/gkDCKA8nYyVwIX7\n"
                + "4N0NjYCcmrpSbloHzCQLU2Zy3RkP1iVdyOTgpwGcoNhgXjLBY9/wIxVFPI1z\n"
                + "p8CSSrAJrIOKdxmQkAFVQb0iGzg2VjbOZ6Y7S5oUlTdeGtpaJDmkGO+zh+Jk\n"
                + "NhAAQP4/h3E4WUkwbJUPNz0gSVYWjm9JERUtpArY16VIRJKH647Sja9zROEF\n"
                + "Be29wCEOxOWpNz3xHGeHaq7Wloz/tGcj0+N/0r51bvsUjBPpUfAVPi6yyYIZ\n"
                + "xP0veEOphkNAy2lLzHgJkjk/NuQoF/pRHUsqaFNSCEgiOk6UBV+ULLnXyEVv\n"
                + "0IaHSo0IRW67LTZjiTAeWOY0fA9eCVU7CuF2TmcV9eJIefcqzskTrLlcd8OM\n"
                + "vHFlGVkvZ4+uPld/QWITlQoRyJ6xIPj+javGgx+0XcNnZRUrk54pF264L0cd\n"
                + "DpYXTDv8AHqr2wDKVLMQRposYXR7PGen9/gR6h5VjvxRlyW9avSk4nsN77Hk\n"
                + "svZ9yxmT8VghUpmnFBk8WxuIOmRiYTwDgD6BLGhfRyOixTCsoDOLW4DNPf1D\n"
                + "NZ2MnhCpZMrLFyw/iQB9KhU8+PQQpRmGzQQK2ep1dnHwAQziyodAefcQ+zgH\n"
                + "PrX/P1t/Ae/JheOE4LwhQKASDH/e2+URNOwPLDbga6ru4iAZXALBeqYgD59A\n"
                + "HUpLJIoJqPripKqOrg9hrz8bSw+CZpykD4sgRjmB9fuB0tUNzCV4vXBO0dqt\n"
                + "KCvbstTFdZfDDGyph7BNRB/qMK6jx0zd7Tix3Cu2FGYBibl+Lo/ZC0cFqe6W\n"
                + "yHTkI+EziSZWX6Q+d0D+zwJjdn5nKT12NypQ/zj62xh49YvxBr0EAS61m4te\n"
                + "I4KxyPcGiTuhhwyI1ucmXNJ1fEMYrsO125wVat01/YNPFTVH9O1bLNMQUj7l\n"
                + "veSJFw/8PWMBxjkHFhFewHryved8PT0s5gkjf8wYELKQS70vHhwM2g0mCAHo\n"
                + "a/VZK8GWM90EAxWPnbZntfhpcg8CyA93aZyZBxIlna6DeksW5m0DofvmQsAT\n"
                + "Bb+fnOG0DLcocLFkynfYpK4TE4JmgjrItpBOY9OcSrt4p63RZ/bxIrmjE1KX\n"
                + "5QfCQfM1uB1/6we43aWFByOuBTMzkMMP9H7xNjmJtn3VbevaFSdddySrKFTh\n"
                + "vmwwt6PpkDqK5iT7gNib/DYqoeWfqFXEzqIdfwpbc0+/3A2vS6SCNmLrg5wh\n"
                + "2PSf2YzJZJSwcn6PF5Q4HG9apdl+nm5GpeyIXFoR7BXL+dtq/MXyJrVih9Iw\n"
                + "dIkxlEitZfLc/9sLKXr3INqKOuzyY7G7IGHPlOYB5+f0Zj9fUhv/A15E0pp2\n"
                + "7gVcL6o1tlDfDoDGl+cSDd7PRvPtzmsQ3rQUeHFdb4QSjYJ+TJq9jSZ88u1L\n"
                + "lZYCYjiiqSUshuE3ekwfNHAnzApY6guDdje6UUCSUBTU8TGIfB8u1P8Zd+lD\n"
                + "GjFi5Z3Ci8MamWA1VivX3mmCzDOAIJ3S04pO+siu01C/Lp1plwSD2YjnIaK9\n"
                + "8ayr+H1ZlXyKbbMzZsEM7N/jcn+vmgtHvDIV7G8A6aH1qcH5W8+vQ52tn9bC\n"
                + "Su/f9uJAR4gCkPCykZEnkuMjFxanv2nj6LYUDdiDo6SsNvQNuUq5uPNDzIwl\n"
                + "XgQO8/RWCCDQLcsJwRAh+LoK+Rf1ST8s24YlBbl3o0PLOGeTy2tgELSgAH9F\n"
                + "0pLZ0Ku/xQgKUkZRpxPuiiA+2mFXA3dhEURK3+LW+EajnDUzhyU14M3WTv03\n"
                + "GZm90svlR8kQJ5kCfl5lweHkOEvNGVRlc3QgVGVzdCA8dGVzdEB0ZXN0Lm9y\n"
                + "Zz7CwXUEEAEIAB8FAl7f8NsGCwkHCAMCBBUICgIDFgIBAhkBAhsDAh4BAAoJ\n"
                + "EOinf2oR0+T9Qd8P/jORcC2rgNkUaLq3K15Kbyos4Vz8hHziFMN1nc0G77+T\n"
                + "tfzhPfXE9keimRuIrD5utipRDK6vG3Osfcy65pb2v8CMbfgysHWRNrSdJej9\n"
                + "hGDYECwP9u21oESZgf0UP2OW02umyg3DQ3jo3Kmnj584JTBDNumZpyJfoVGU\n"
                + "X59PbV/8AbHhX8qotXTh92x6KOn/DB6s/krD1xriEyGZ/Tuh/jC9GhioDw7O\n"
                + "SFztM+HwjBIg+I5eIoPlOumeil5kfEDPnOfXe5grEVfCfrYQGzR7Fnhb2j/K\n"
                + "KEdvghrzHY8F6Io8Kg3SL8W/5Dp489vXbxNcuNwrYZoMFwJrBZ+NvIl6K3ux\n"
                + "nUgrro4T3HWbioySdLFkwOnNMbgKYewbvgAosZVS+XqpDuvlxrVNgjfFXGt0\n"
                + "lWscr0WgIpcg75mkAF55iHrzr5bXdXaybBIxAPVPrWkbFs05I9ldibk5Xl4a\n"
                + "aUN7ukGhndaa+YyGRv13Sr/Ks6tcNZtik9EupfN18C6jv4Vauq4j/2cqewiK\n"
                + "YEW918Dt4ooqnQTcuT+8Kxc052MbzbWayjTOOyHVrlpNn06QwuU/YN9wUGFK\n"
                + "+oBvbZmWSmApMLap+pauVOYCbW2qILC4m5zayJxLxwt2J4Om9Q87o6zzh2aM\n"
                + "/zbDkwWSXJMMclriPEqrxA3zD0CsOwhXLtelu08vx8aGBF7f8NsBEACh/BCz\n"
                + "s3jVFaj3R9NsP42XY23roNZYeKZ/s4JXUjRC8BUt0EJ4BDnYK5AYyut7dnTv\n"
                + "09RJDtsKrFithhkhf2Ct5pjk/FMLb3ZuEfEKv0bu09SLYWu+bG8BYHfD3Xw7\n"
                + "0WQbPXzbb2pPyZEidQJWXjV1ezMXH98BuTLG4T9TBvuzDqVsq+6Xd7NWMx/q\n"
                + "r0oxsYtrLehNQndh361zXHY62GKKJP6qJTAKAo5GbUt49Uz+/D8sFJOZhCn8\n"
                + "/2hUOi1hQYuYsgu1vnDqj7uwS/q117YWtsU63gkSK0ipQpAFZ8sl5bJJ79e+\n"
                + "0dd2tA+uEAMGxrzvfBYr5vbI1WULU6dQZxqk1GIunKAP1KEYcvfA/gqjbbzC\n"
                + "SEBbc2IJf7nygn07Enzhgu9DJMZWtdoVPxbYgWPYLTx8qHOft7UOa1381/fN\n"
                + "0W9rz6oJXRZXDsmkxcs3uiWqgiimVcsLZLMniABVxP0/HHDhxCGaTWVTCDj1\n"
                + "3uOQQphfkqeyu9xp3vIjgx9YJCrzSEMrEO4HEM64/RxPEpG3NcavNUNIjZxc\n"
                + "EWROJoJC0TA6wemy8Cg7nsdAWZb4hF4V9YQjcnZsLnP3qNXnKzD7ZKKC94a9\n"
                + "nLpnHGzwcmBgHTn/anpv2RrLvyAQIpbyt1SjVgLF26m0OwDWHV6e3zHw5Age\n"
                + "Gy5cMT4srWN8K6QR5wARAQAB/gkDCIl32qojWmrV4AYs1mUjjr8P0P5qVpPC\n"
                + "d2bSwMcewpcTkT2ytpB34gY5MSJdCAx3jFXTz3vRiAw5rFMWv7OiA+0kAadn\n"
                + "CdoAQCe6xG1PF5g5QrpeCwAddwDD4CVcHTuZEMhZzsA03IJkNlDq+rviDaSs\n"
                + "G8My4ui2jPhHJ+em/svltZ430D5dhXliTUDC9xbPfgeNobSL50oHU5W3854p\n"
                + "0k2DTVhSc1gZPEQVWt1GW1yIJ4BHxF2oX1MGeqph/K4++QVCwnT//28SymMs\n"
                + "RUyCMwFD4Df6YUuffrH6DcytpOOoAi7iuF7ceetMPm0yyOwy8VnNxEFjk60f\n"
                + "+3uepfPxdm+h3Uijbtk8jx1X62dBQLfkdUsG/T1VcXxNIxSszQcSLgqfK4Gj\n"
                + "rGH7ydD/IIoWhvktAGXBqbIzZALK93xgnGGUQdllBqUNJqtc0dLzOn6yDbHK\n"
                + "nz/Rl/9Iua9twMaGdQlQoWNNOGmfsd7nV4CCdZ0vxssdJHbFjqEB1oqoCsAw\n"
                + "QKhO4nITvF+NNSnwGxnFpUuNfaPxWmKmBUQvN3VFYWnJ7th6YhYd15/y0J71\n"
                + "n6HMsNVnj/L087+1zxVj2ZIG5RYgsI0oqAmZE13FjNe/rxQ9M8foCdSc49wQ\n"
                + "PH48S0WlO6AL29iY/MuKN0sK+qDpVHswlNGNvorANiTjzCCsZF+0EiGn+0X5\n"
                + "Hh+zbxoJN/boHkTB9fJFeXt7VoJ2TbBK2a/beGXjItSCWSfNlhQJ/+NJpUnj\n"
                + "guvWRCqJDMy4rEhTxWwhJ2GCVrtGl32of9tDwa8xoaizUYkSKgXwzh2dvBYj\n"
                + "ldDFiE/TpO5auxSK92Ii9NMHurLoBQmvaxM4kkg0H0d6DCFW91MRZ1i1+vzi\n"
                + "k9XLFXuAWPRZfByw3/JfQKbi+hPJ/brUPgk3dEV23vs4EOJYSYzUav4aObiQ\n"
                + "4OYvuZCfs/p/+YvwalvBTs2h2zGeMtExztoZbkbzmM2BVc44TCDwj1NHWqZ+\n"
                + "vXEdSndhAzFSbQ9elVIeaWCIhAi+VRN6iQ2IEv7QSDunKb1UHRV8Mdag8X8h\n"
                + "X8iwUasiDi6nB1K+v2ma/E3NhlI7N5X4whAfyYQ/pOOh3pJgGQTiLnhiNBZU\n"
                + "ZKzMblg1PwSOInZ5HB0ltEadIopP1CAETTM9hOFhioi8+62ZSzQCwan5s7Um\n"
                + "bURgyGpm1+BAvC3D8PX6b67n/cOduofHnk5o1GZWqRjbmz46zUnPrq2kwiy8\n"
                + "DuAOX5eni5eAjp8GlB89ePztdwU5P5cp1U3jpAtiX9OqH24YBERi7Z1zA+h3\n"
                + "4JHWv7op3l1w2VCIxVtjten9c6UFoGy7pwE0eQ1E8Ni+uSVcN3BZGFgIsImr\n"
                + "PRtofFvGIMBPU5SvLv/DDzjTreQAiFDiloUocn10x2d4wYj/eHmq4tzpoN1O\n"
                + "4WfanhpXBarTnKPs7LLGqiUjfpK8TOfy2AxXCab5ASjD6upPSutnai/kci4E\n"
                + "JtT/yoXpQtzf8Ih1ly1nbz/WU3Hg0tpIuMn2qdCDNIoredxM+VqKzo6FqAfG\n"
                + "oaDLLbJuDb5HNOzL7zBBaC1L0F6GrJ7IbGRULKPnxbfYl7XSFHwtETaNh4PA\n"
                + "6PhD9YsamYVuQx1BmBXzL51QurcKh5nyl3Y1hmBDQRFFXnWYYvdk67cT4qgl\n"
                + "kWyAznl73yv5bbI6tcFPyi/rIvTidocvL4x3mSZ0w1yGzHMGkk/5HG33f0As\n"
                + "8pJL4Qra6XHJU7bBCpHOx7wUykLGaxDLG/tQ/vvwi/osp/Pj4wLX/c1kOlv1\n"
                + "gaR3Tg3CwV8EGAEIAAkFAl7f8NsCGwwACgkQ6Kd/ahHT5P2PNQ/9HZOBbips\n"
                + "9IlmQFXgyTpHxbhEPEbULeGuptP1PhrfSxJ3+vgXIlbKtweXd4uP0ybuJZc1\n"
                + "ekV+QZH7XNApBo2NNT27oYH1tuvDWwiq0RX+MToWhRhaSQdP/iayF6mhA8B0\n"
                + "RW/BwXb/GLyzJ+oHTdwjX1grAcY6CzkNP96/R+kSYg2rem0Mqb2b0VyQfehy\n"
                + "U00mG/BfncI4GniJDt2XDkNTDFZe9ma7rJiDMSm3+VBtiZ6/8i7tOokWi0OO\n"
                + "hdqonkW6Tc4be2OZBHXfc8BcQwLZyKK396LrgeDJSAehjtw+/Eg3AChoIrUM\n"
                + "KDHlGcMjeJY1bIDGXtsOMIZdPq3gFiNIyj9ue2GTJk0pIcum00FJHR+fd0qB\n"
                + "1JOykCMM5zzowL0isFKaApVgV3kOemNXxgPKRYr5HHZUt7VrwqbIdjnhUAm8\n"
                + "K0xJ8v6LNwzz/KzBTKwPQXTedzf8cjwRLF+ekzm8iAXyI4pagTCq+3ZOsYxA\n"
                + "bInmOCRVWVd4e3mgQwL/8MOvYtr6qhCzYLc+ou2Tb0dxbdnYzXmQ4UApakwR\n"
                + "xNjTJ2RxXRvl5drvkhHuNjmPl6LS1t1XZ68tZxAG7jbUeq/RUAKIFQtJ+mMi\n"
                + "3qJ4DPhl15W71/fVvvCqjvulqp7H0II8mrt6/2syCIkx5t4MZmO0pQiiESkY\n"
                + "jkzoz0lzSY7rxmM=\n"
                + "=Uwrk\n"
                + "-----END PGP PRIVATE KEY BLOCK-----";

        String pubkeyString = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                + "\n"
                + "xsFNBF7f8NsBEACt75Hr0m4Tvrqht/WwwnAnplP8LMY45y743NMW5VAtmgM/\n"
                + "N0GyTJFG+Gt1THEhQVSVXCyhx837DFUj7dToEH7+2cJzaUcFphtBlFPc3Qpr\n"
                + "nCH2uIW2wYW3+Mr27oLZ5SYVCbErN6OCG4bcYyDlKY1zay2iQmnPaoEBf/CI\n"
                + "V092HTtqb8w7ABhRpDGfKQNy+/DNsJcxbgGlwrnftEpfaPmpAvXCG9bv34yD\n"
                + "3eKGmG5rhFbplqFd89cYw214JFW8f/tTNp2xCSYdZiBsbUcXdeoMAYiz4Bhl\n"
                + "q0KbHHf8IWEZc/vMjefoV9bb9XW0DsnRNZs4ukg3q7ta+qngFd/DfbHutUQR\n"
                + "Q0Z9oiUS0A7l5stlwppLyTYQCv8O58FUerVAxqJKHiB47G2hq7RSbi/7M2hD\n"
                + "xdI5Fn37HvfZ8Rv617YTlUIZNE9QkoQtyBm48GRNT89r9rncNCggfY4aH9Z7\n"
                + "Me5/rfOyhosDyhH5G858F4IzeJbrPzoZWux7aYSdl33X/Jlz830nTmbS5cgm\n"
                + "0n/SySRqErxI2g1JLuit2lf5//ANI6EaKpI8xJAk/pX+xHHzhXvAoIJl4qe4\n"
                + "Mgv17xz9J4NUuQtMRhlyJPnFe9exZ06h7/qCu5tpzDY5o258RD55zmclKgSP\n"
                + "9A5YejI1/cJHAHFJgXnJFNTRS1ITguWcAkbrKwARAQABzRlUZXN0IFRlc3Qg\n"
                + "PHRlc3RAdGVzdC5vcmc+wsF1BBABCAAfBQJe3/DbBgsJBwgDAgQVCAoCAxYC\n"
                + "AQIZAQIbAwIeAQAKCRDop39qEdPk/UHfD/4zkXAtq4DZFGi6tyteSm8qLOFc\n"
                + "/IR84hTDdZ3NBu+/k7X84T31xPZHopkbiKw+brYqUQyurxtzrH3MuuaW9r/A\n"
                + "jG34MrB1kTa0nSXo/YRg2BAsD/bttaBEmYH9FD9jltNrpsoNw0N46Nypp4+f\n"
                + "OCUwQzbpmaciX6FRlF+fT21f/AGx4V/KqLV04fdseijp/wwerP5Kw9ca4hMh\n"
                + "mf07of4wvRoYqA8Ozkhc7TPh8IwSIPiOXiKD5TrpnopeZHxAz5zn13uYKxFX\n"
                + "wn62EBs0exZ4W9o/yihHb4Ia8x2PBeiKPCoN0i/Fv+Q6ePPb128TXLjcK2Ga\n"
                + "DBcCawWfjbyJeit7sZ1IK66OE9x1m4qMknSxZMDpzTG4CmHsG74AKLGVUvl6\n"
                + "qQ7r5ca1TYI3xVxrdJVrHK9FoCKXIO+ZpABeeYh686+W13V2smwSMQD1T61p\n"
                + "GxbNOSPZXYm5OV5eGmlDe7pBoZ3WmvmMhkb9d0q/yrOrXDWbYpPRLqXzdfAu\n"
                + "o7+FWrquI/9nKnsIimBFvdfA7eKKKp0E3Lk/vCsXNOdjG821mso0zjsh1a5a\n"
                + "TZ9OkMLlP2DfcFBhSvqAb22ZlkpgKTC2qfqWrlTmAm1tqiCwuJuc2sicS8cL\n"
                + "dieDpvUPO6Os84dmjP82w5MFklyTDHJa4jxKq8QN8w9ArDsIVy7XpbtPL87B\n"
                + "TQRe3/DbARAAofwQs7N41RWo90fTbD+Nl2Nt66DWWHimf7OCV1I0QvAVLdBC\n"
                + "eAQ52CuQGMrre3Z079PUSQ7bCqxYrYYZIX9greaY5PxTC292bhHxCr9G7tPU\n"
                + "i2FrvmxvAWB3w918O9FkGz18229qT8mRInUCVl41dXszFx/fAbkyxuE/Uwb7\n"
                + "sw6lbKvul3ezVjMf6q9KMbGLay3oTUJ3Yd+tc1x2OthiiiT+qiUwCgKORm1L\n"
                + "ePVM/vw/LBSTmYQp/P9oVDotYUGLmLILtb5w6o+7sEv6tde2FrbFOt4JEitI\n"
                + "qUKQBWfLJeWySe/XvtHXdrQPrhADBsa873wWK+b2yNVlC1OnUGcapNRiLpyg\n"
                + "D9ShGHL3wP4Ko228wkhAW3NiCX+58oJ9OxJ84YLvQyTGVrXaFT8W2IFj2C08\n"
                + "fKhzn7e1Dmtd/Nf3zdFva8+qCV0WVw7JpMXLN7olqoIoplXLC2SzJ4gAVcT9\n"
                + "Pxxw4cQhmk1lUwg49d7jkEKYX5Knsrvcad7yI4MfWCQq80hDKxDuBxDOuP0c\n"
                + "TxKRtzXGrzVDSI2cXBFkTiaCQtEwOsHpsvAoO57HQFmW+IReFfWEI3J2bC5z\n"
                + "96jV5ysw+2SigveGvZy6Zxxs8HJgYB05/2p6b9kay78gECKW8rdUo1YCxdup\n"
                + "tDsA1h1ent8x8OQIHhsuXDE+LK1jfCukEecAEQEAAcLBXwQYAQgACQUCXt/w\n"
                + "2wIbDAAKCRDop39qEdPk/Y81D/0dk4FuKmz0iWZAVeDJOkfFuEQ8RtQt4a6m\n"
                + "0/U+Gt9LEnf6+BciVsq3B5d3i4/TJu4llzV6RX5Bkftc0CkGjY01PbuhgfW2\n"
                + "68NbCKrRFf4xOhaFGFpJB0/+JrIXqaEDwHRFb8HBdv8YvLMn6gdN3CNfWCsB\n"
                + "xjoLOQ0/3r9H6RJiDat6bQypvZvRXJB96HJTTSYb8F+dwjgaeIkO3ZcOQ1MM\n"
                + "Vl72ZrusmIMxKbf5UG2Jnr/yLu06iRaLQ46F2qieRbpNzht7Y5kEdd9zwFxD\n"
                + "AtnIorf3ouuB4MlIB6GO3D78SDcAKGgitQwoMeUZwyN4ljVsgMZe2w4whl0+\n"
                + "reAWI0jKP257YZMmTSkhy6bTQUkdH593SoHUk7KQIwznPOjAvSKwUpoClWBX\n"
                + "eQ56Y1fGA8pFivkcdlS3tWvCpsh2OeFQCbwrTEny/os3DPP8rMFMrA9BdN53\n"
                + "N/xyPBEsX56TObyIBfIjilqBMKr7dk6xjEBsieY4JFVZV3h7eaBDAv/ww69i\n"
                + "2vqqELNgtz6i7ZNvR3Ft2djNeZDhQClqTBHE2NMnZHFdG+Xl2u+SEe42OY+X\n"
                + "otLW3Vdnry1nEAbuNtR6r9FQAogVC0n6YyLeongM+GXXlbvX99W+8KqO+6Wq\n"
                + "nsfQgjyau3r/azIIiTHm3gxmY7SlCKIRKRiOTOjPSXNJjuvGYw==\n"
                + "=ckUo\n"
                + "-----END PGP PUBLIC KEY BLOCK-----";
        addPublicKey(email, pubkeyString);
        addPrivateKey(email, privkeyString);
        System.out.println("Public key Loaded");
    }

    private static InMemoryKeyring createKeyringInMemory(final String protectionPassPhrase) throws IOException, PGPException {
        InMemoryKeyring inMemoryKeyring = null;
        if (protectionPassPhrase != null) {
            inMemoryKeyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPassword(protectionPassPhrase));
        } else {
            inMemoryKeyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
        }
        return inMemoryKeyring;
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

    /**
     * load Publickey into keyring and verify if the email provided is the owner
     * of teh key
     *
     * @param email
     * @param keyString
     * @throws Exception
     */
    private void addPublicKey(String email, String keyString) throws Exception {
        if (keyring != null) {
            keyring.addPublicKey(keyString.getBytes());
            int counter = 0;
            if (getUserIDfromEmail(email, false) == null) {
                throw new Exception("Public key provided for " + email + " not consistent");
            }
        } else {
            throw new Exception("Keyring not initialized");
        }
    }

    /**
     * load Publickey into keyring and verify if the email provided is the owner
     * of teh key
     *
     * @param email
     * @param keyString
     * @throws Exception
     */
    private void addPrivateKey(String email, String keyString) throws Exception {
        if (keyring != null) {
            keyring.addSecretKey(keyString.getBytes());
            int counter = 0;
            if (getUserIDfromEmail(email, true) == null) {
                throw new Exception("Public key provided for " + email + " not consistent");
            }
        } else {
            throw new Exception("Keyring not initialized");
        }
    }

    /**
     * load Publickey into keyring and verify if the email provided is the owner
     * of teh key
     *
     * @param email
     * @param keyString
     * @throws Exception
     */
    private String getUserIDfromEmail(String email, boolean isPrivate) throws Exception {
        String userID = null;
        if (keyring != null) {
            if (isPrivate == false) {
                for (PGPPublicKeyRing key : keyring.getPublicKeyRings()) {
                    for (Iterator i = key.getPublicKeys(); i.hasNext();) {
                        PGPPublicKey ppk = (PGPPublicKey) i.next();
                        for (Iterator k = ppk.getUserIDs(); k.hasNext();) {
                            String uid = (String) k.next();
                            if (uid.contains(email)) {
                                userID = uid;
                                break;
                            }
                        }
                    }
                }
            } else {
                for (PGPSecretKeyRing keyR : keyring.getSecretKeyRings()) {
                    for (Iterator i = keyR.getSecretKeys(); i.hasNext();) {
                        PGPSecretKey psk = (PGPSecretKey) i.next();
                        for (Iterator k = psk.getUserIDs(); k.hasNext();) {
                            String uid = (String) k.next();
                            if (uid.contains(email)) {
                                userID = uid;
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            throw new Exception("Keyring not initialized");
        }
        return userID;
    }
}
