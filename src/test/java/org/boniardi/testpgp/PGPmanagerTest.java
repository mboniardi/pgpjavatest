/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.boniardi.testpgp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author mboniardi
 */
public class PGPmanagerTest {
    
    public PGPmanagerTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() {
    }
    
    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of encrypt method, of class PGPmanager.
     */
    @Test
    public void testEncrypt_String_String() throws Exception {
        System.out.println("decrypt");
        String toBeEncrypted = "this is the etxt to encrypt";
        PGPmanager instance = new PGPmanager();
        String cipherText = instance.encrypt("test@test.org", toBeEncrypted);
        String result = instance.decrypt(cipherText);
        assertEquals(toBeEncrypted, result);
    }

    /**
     * Test of encrypt method, of class PGPmanager.
     */
    @Test
    public void testEncrypt_String_byteArr() throws Exception {
        System.out.println("decrypt");
        String toBeEncrypted = "this is the etxt to encrypt";
        PGPmanager instance = new PGPmanager();
        String cipherText = instance.encrypt("test@test.org", toBeEncrypted.getBytes());
        String result = instance.decrypt(cipherText);
        assertEquals(toBeEncrypted, result);
    }

    /**
     * Test of decrypt method, of class PGPmanager.
     */
    @Test
    public void testDecrypt() throws Exception {
        System.out.println("decrypt");
        String toBeEncrypted = "this is the etxt to encrypt";
        PGPmanager instance = new PGPmanager();
        String cipherText = instance.encrypt("test@test.org", toBeEncrypted);
        String result = instance.decrypt(cipherText);
        assertEquals(toBeEncrypted, result);
    }


    
}
