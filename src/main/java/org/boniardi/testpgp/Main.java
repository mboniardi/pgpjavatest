/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.boniardi.testpgp;

/**
 *
 * @author mboniardi
 */
public class Main {

    public static void main(String[] params) {
        Main myapp = new Main();
        myapp.encryptFile();

    }

    public void encryptFile() {
        
        String textToEncrypt = "Questo e' il testo che deve essere criptato";
        try {
            // this class is generated by @autowire
            PGPmanager pgpMng = new PGPmanager();
            // this is the action
            String encrString = pgpMng.encrypt(textToEncrypt);
            System.out.println(encrString);
        } catch (Exception e) {
            e.printStackTrace();
        }

        /**
         * NB if you wand to save the encrypted string in a file, the naming
         * convention is original_name.original_extention.pgp/asc example
         * myfile.csv -> myfile.csv.pgp or myfile.csv.asc myfile.xls ->
         * myfile.xls.pgp or myfile.xls.asc
         */
    }

}
