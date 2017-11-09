/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package passwordmanager;

import commandLineArgsParser.CommandLine;
import commandLineArgsParser.CommandLineParser;
import commandLineArgsParser.DefaultParser;
import commandLineArgsParser.HelpFormatter;
import commandLineArgsParser.Option;
import commandLineArgsParser.Options;
import commandLineArgsParser.ParseException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Encoder;

/**
 *
 * @author root
 */
public class main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException 
    {
        // Command line arguments parser usage is based from:
        // https://stackoverflow.com/questions/367706/how-to-parse-command-line-arguments-in-java
        // Using Apache Commons CLI
        Options options = new Options();

        Option optService = new Option("s", "service", true, "service which uses the password");
        optService.setRequired(false);
        options.addOption(optService);
        
        Option optAddress = new Option("u", "address", true, "service address");
        optAddress.setRequired(true);
        options.addOption(optAddress);
        
        Option optUsername = new Option("n", "username", true, "account username");
        optUsername.setRequired(true);
        options.addOption(optUsername);
        
        Option optPassword = new Option("p", "password", true, "account password");
        optPassword.setRequired(true);
        options.addOption(optPassword);
        
        Option optComment = new Option("c", "comment", true, "entry comment");
        optComment.setRequired(false);
        options.addOption(optComment);
        
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try 
        {
            cmd = parser.parse(options, args);
        } 
        catch (ParseException e) 
        {
            System.out.println(e.getMessage());
            formatter.printHelp("utility-name", options);

            System.exit(1);
            return;
        }

        String Service = cmd.getOptionValue("service");
        String Address = cmd.getOptionValue("address");
        String Username = cmd.getOptionValue("username");
        String Password = cmd.getOptionValue("password");
        String Comment = cmd.getOptionValue("comment");
        doEncryption(Username);
        
    }
    
    public static String doEncryption(String Entry) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] EncryptionKey = (Entry).getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        EncryptionKey = sha.digest(EncryptionKey);
        EncryptionKey = Arrays.copyOf(EncryptionKey, 16);
        
        Key newEncKey = new SecretKeySpec(EncryptionKey,"AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, newEncKey);
        byte[] EncryptedData = cipher.doFinal(Entry.getBytes());
        return new BASE64Encoder().encode(EncryptedData);
    } 
}
