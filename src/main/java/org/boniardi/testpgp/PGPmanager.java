/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.boniardi.testpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.Random;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 *
 * @author mboniardi
 */
public class PGPmanager {

    private String internalPassPhrase = "";
    private InMemoryKeyring keyring = null;

    PGPmanager() {
        try {
            //create a pwd to protect keyring
            byte[] array = new byte[7]; // length is bounded by 7
            new Random().nextBytes(array);
            internalPassPhrase = new String(array, Charset.forName("UTF-8"));
            //create keyring
            keyring = createKeyringInMemory(internalPassPhrase);
            //load keys from ... configuration
            loadKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @param sourceString
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws SignatureException
     */
    public String encrypt(String sourceString)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        return encrypt(sourceString.getBytes());
    }

    /**
     *
     * @param sourceBytes
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws SignatureException
     */
    public String encrypt(byte[] sourceBytes)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        installBCProvider();
        ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();
        String recipient = getRecipientFromPublicKey();

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

    private void loadKeys() throws Exception {
        // to rewrite with upload from Configutation
        String pubkeyString = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                + "\n"
                + "mQINBFokXswBEACzQqY5X0uOk2O1BW+AhZV0vCO+nlmzrdC+ytGYYpqDVs9zbKBi\n"
                + "TvHreGYkhZMk6CHgh2fJcR2SsfpukGhsmTjOIdAOkC5VMeU2DfokgonZM0aYN1mj\n"
                + "Q6Kotf28TI9zYxg6lYNhWInGLMC569bL5hKzj8jo3ez6PW5q9AEnczN+YrPmTPt/\n"
                + "HsmCAVIt0yGxMXrq/bHdeZOlQM7bap46UUQp0shrZ5n5hu/vU58voZPEG70K16AZ\n"
                + "EbKCRUzNHMMbzQquPtLGyuD/FDgbt4Q09No7HXNO+xEHgc1yM+YMX5gTaori0TRL\n"
                + "Jx64b4+WDjGbeiyRUqsIHEfuAYsILeGZ1ovCEODbCv6+Vza1S6guK7Ch2+SvEsvB\n"
                + "MDFuL2YZ/+jLnwTwLILUxlVTAbk2yoRwOuB9oJIhctWBxxTqiqax3xqRrks3J9/S\n"
                + "M7tyJ9x/5h7WKDp5luy6I61V4QObi0pXlgGs0RyilndL7DfLx6wwZhY88ryQAfUs\n"
                + "frqKMp9VGqL7bea9o6o7i3sLOiNlKkgre21OYinodzruCCCH7JwgyKHnGOklb/Zh\n"
                + "x6Psr0UyGS0LbS7v4a0SZOjCvnvWDk5fRGqOwYAxoYwNF9MlQcjIE5uILncYL01Z\n"
                + "W+ktlLiDm3ma8eRvWMV1L7WGbRIsA3OjoQGN/RPt6qx8dOo4a6/P628pgwARAQAB\n"
                + "tDRNYXJjbyBCb25pYXJkaSBHbWFpbCA8bWFyY28uYm9uaWFyZGlAbGFzdG1pbnV0\n"
                + "ZS5jb20+iQJUBBMBCAA+FiEEXsRGdzzdgHZhWpE65AXmUJQJ0KgFAlokXswCGwMF\n"
                + "CQeGH4AFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQ5AXmUJQJ0Kg1WhAAmjdW\n"
                + "hpmWgf7DDj3Z9Wwekf0v3k+Ni7uPbIJRmZZB47DAd7GDnRqvLFGiYjshxizFC3sb\n"
                + "PVgdt9r5zqBZW8rHFeR8UnvLZLnkeJt/0G9MUy46kPVL1RaBJ43miAKAHtjwslA3\n"
                + "zY8sYBlnWE/7UKUJ+RYzmqkYfM4RPrsKGa/kMLJj+PcJe81Ft2NW+sl1YGGiGEFL\n"
                + "FOY0ULj3t70q1KPMuj09bH9U6rQKbRDYhS9FpmMuOVWX+634+dFBl/z509tdFWx9\n"
                + "uawbGg9cRWR2mKwj1dy2JtuwIHyQfiC8EdgIf4Lni0jjyI8jGIicv4Q/zKlOcAj+\n"
                + "0bO9gfwKDr6P3CL1a5vGN/HsJQ0mVO6L2F1HPawzmwIwYZBAKHvyah+ljQYh1Jfm\n"
                + "GGR4adP4nSb2OM9KIbX+kly/kFV89iRCb6jC4E+ey1gsToXuwjFH73UUKrYtuL9u\n"
                + "1romzmP+GlKsKq5JWWh+18uqzdpj4x4aJ6lGKTfbV48NTQI96LLOFS5TiCmoiNe9\n"
                + "Q4e9wc0VOz0nHkD+wZ/3TEc+Z/0C0IkVH4OVhXnrCcxX2Fezwu2VVXpJSMunq6P1\n"
                + "Fst9qdUcrbl4J0fTB7kN8m0znpno3Nz3KcuqB+g+ulHj+2ZxUzZx/CZSgM/knOfj\n"
                + "NfZ4E9aYI6KvoZOLNrE4WKclbYUfQH0Ga0cXx6a5Ag0EWiRezAEQAKctYd6S+zZR\n"
                + "FFLQH+uut2N1D/4RYRkjHZu3aIN0JgaWtAtbKdNhaY2rpTrI+HchvVGXmvxSL+j5\n"
                + "iriWB4uk2a/0cV0A5nhL8Nz9Xef8LHUGay4Vtk4rdVnnLVArFXoYZ9TcwsnsazlE\n"
                + "bB76qedbhQgX2swwnH/bhUO/foOUSpdBAG9wxCb7ZuDXNEtwEa8BSs7bsqx22whj\n"
                + "lLJ6THFUss4g0I5dW+hPUTWTkL5Q0YnOfBYSfEyuj4cf1BQ9ZD20dRfsJuD3ttId\n"
                + "+CyVBJCLuyMX2svob3hJQzFqJMXlQr9QWKlSQ5+ipFO1fETztKbH2zvLkOdMMY0d\n"
                + "NH2ruThHbC056UwxeZ1S/03EUD0iK/6ezX2P7UBV4BCHfumERZ0djBJWqVl2Lc54\n"
                + "6+BV4pIaCH+OFFgsjRKEQRmPvpyV7ADZGtknMGsJF68rJZbyCqTP2lMM6ylBTQcT\n"
                + "kub9+W/Hs9bgWaIrB0fVitPs+bMSiXKfyFaUIw/icGLQ9oiR0PGr0TDMRCI4Yhg0\n"
                + "+wAYWAyuFiwd7v2dLfK87NpZF6EkwaQVBVwjTobYTCoETDhrunySENLBSyvLhKO0\n"
                + "eiSdnu6YLDVhbG6DbieC94M55ffg50X49AN9NiPx+3m/M20vE9DtEmFhMWY+/Nnb\n"
                + "CebO2BsLczpMbEsgXh0Tj1Jl2gAq6jupABEBAAGJAjwEGAEIACYWIQRexEZ3PN2A\n"
                + "dmFakTrkBeZQlAnQqAUCWiRezAIbDAUJB4YfgAAKCRDkBeZQlAnQqDaVEACRS/Hm\n"
                + "MCZHU0CVHV0Imag63B6B8NacChpfvN+uhd9kCUUq9m0LzWPEMPvWiCuZyjwUpexu\n"
                + "HfcI7nmVk19rMLLkFPxp0Kr8Q7QqEClBu0SlLCYp5kXyqwgzSzTV8hQEMfCYhvhn\n"
                + "JexvzclxZJYcJwv/VNtUVqJ/VvHH38nJfzgLsxdohChoLOOVk2joHh6caQxfJzvZ\n"
                + "l12yIsLfzbAtxFtB9SjFr+qlBCCVc8HMjFy53oFBYSx/JYd/vUwoqmPETM1J6Dwy\n"
                + "TuuKxhEVFTqQ8+J0SsnpLtOz5ftv/RrU9D7Pf6PWJNtWcrrtmYW7FKTkgUijTT+G\n"
                + "Iaknrg+uLWa8H0bfYEXyF7mMtM/G81BC7owC4TCIt2Cn1ABy4eg2/9EFpuxKfPOY\n"
                + "vNM+Yt6ZxZwj/sa4o5Sp5OL1nZp0AKAlYBYVexDiI2w5A4vbaGbNMnjEFe3PE7Ev\n"
                + "ys4zycHzJXTvr2PwnNIC2yIOJ/sZjFj/NG16kjo9zyWd4XjD+7NWhX1aGEyEZDWI\n"
                + "U1r3QJM4USiEugMFY7IBsnbRDZdR+6X+lHDCeAt+3yFk9yL+iThOuCCGJ0aGhLr7\n"
                + "kgu/kru3vEvFjEJ3TCO9j3hCLKKUUhihfkstYNdKQS6z2e3DTzc4iKiPddExWNFS\n"
                + "L42uvTZOKNvgYdVE9JB603l6ls/bnIJAOo/hfA==\n"
                + "=BysJ\n"
                + "-----END PGP PUBLIC KEY BLOCK-----";
        keyring.addPublicKey(pubkeyString.getBytes("US-ASCII"));
        System.out.println("Public key Loaded");
    }

    private static InMemoryKeyring createKeyringInMemory(final String protectionPassPhrase) throws IOException, PGPException {
        InMemoryKeyring keyring = null;
        if (protectionPassPhrase != null) {
            keyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPassword(protectionPassPhrase));
        } else {
            keyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
        }
        return keyring;
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

    private String getRecipientFromPublicKey() {
        String recipient = null;
        try {
            for (PGPPublicKeyRing key : keyring.getPublicKeyRings()) {
                for (Iterator iterator = key.getPublicKey().getUserIDs(); iterator.hasNext();) {
                    recipient = (String) iterator.next();
                }
            }
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
        return recipient;
    }

}
