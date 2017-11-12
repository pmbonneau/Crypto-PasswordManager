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
import jsonParser.JSONObject;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.LineNumberReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jdk.nashorn.internal.parser.JSONParser;
import sun.misc.BASE64Encoder;

/**
 *
 * @author root
 */
public class main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException, Exception 
    {
        // Command line arguments parser usage is based from:
        // https://stackoverflow.com/questions/367706/how-to-parse-command-line-arguments-in-java
        // Using Apache Commons CLI
        Options options = new Options();

        Option optAddEntry = new Option("a", "add", true, "add an entry to password manager");
        optAddEntry.setRequired(false);
        options.addOption(optAddEntry);
        
        Option optReadEntries = new Option("l", "read", true, "read entries from password manager");
        optReadEntries.setRequired(false);
        options.addOption(optReadEntries);
        
        Option optService = new Option("s", "service", true, "service which uses the password");
        optService.setRequired(false);
        options.addOption(optService);
        
        Option optAddress = new Option("u", "address", true, "service address");
        optAddress.setRequired(false);
        options.addOption(optAddress);
        
        Option optUsername = new Option("n", "username", true, "account username");
        optUsername.setRequired(false);
        options.addOption(optUsername);
        
        Option optPassword = new Option("p", "password", true, "account password");
        optPassword.setRequired(false);
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

        String BagPasswordWrite = cmd.getOptionValue("add");
        String BagPasswordRead = cmd.getOptionValue("l");
        String Service = cmd.getOptionValue("service");
        String Address = cmd.getOptionValue("address");
        String Username = cmd.getOptionValue("username");
        String Password = cmd.getOptionValue("password");
        String Comment = cmd.getOptionValue("comment");
        
        File KeyBagFile = new File("keybag.txt");
        if (KeyBagFile.exists() == false)
        {
            //Scanner inputReader = new Scanner(System.in);
            //System.out.println("Please enter new manager password.");
            //String ManagerPassword = inputReader.nextLine();
            createBag();
        }
        
        if (BagPasswordRead == null)
        {
            String EncryptedService = doEncryption(Service,BagPasswordWrite);
            String EncryptedAddress = doEncryption(Address,BagPasswordWrite);
            String EncryptedUsername = doEncryption(Username,BagPasswordWrite);
            String EncryptedPass = doEncryption(Password,BagPasswordWrite);
            String EncryptedComment = "";
            if (Comment != null)
            {
                EncryptedComment = doEncryption(Comment,BagPasswordWrite);
            }

            FileWriter writefile = new FileWriter("keybag.txt", true);
            FileReader readfile = new FileReader("keybag.txt");
            Path Path = Paths.get("keybag.txt");
            LineNumberReader LineCount = new LineNumberReader(readfile);
            String ActualLineCount = Long.toString(Files.lines(Path).count());
            JSONObject obj = new JSONObject();
            obj.put("Line", ActualLineCount);
            obj.put("Service", EncryptedService);
            obj.put("URL", EncryptedAddress);
            obj.put("Name", EncryptedUsername);
            obj.put("Password", EncryptedPass);
            obj.put("Comment", EncryptedComment);
            writefile.write(obj.toString());
            writefile.write("\r\n");
            //writefile.write(ActualLineCount + "|$|" + EncryptedService + "|$|" + EncryptedAddress + "|$|" + EncryptedUsername + "|$|" + EncryptedPass + "|$|" + EncryptedComment);
            writefile.close(); 
        }
        
        if (BagPasswordWrite == null)
        {
           Path Path = Paths.get("keybag.txt");
           List<String> lines = Files.readAllLines(Path);
           for (int i = 0; i < lines.size(); i++)
           {
                JSONObject obj = new JSONObject(lines.get(i));
                System.out.println(obj.get("Line"));
                String DecryptedService = doDecryption(obj.get("Service").toString(),BagPasswordRead);
                System.out.println(DecryptedService);
                String DecryptedAddress = doDecryption(obj.get("URL").toString(),BagPasswordRead);
                System.out.println(DecryptedAddress);
                //String DecryptedUsername = doDecryption(obj.get("Name").toString(),BagPasswordRead);
                String DecryptedUsername = "*****";
                System.out.println(DecryptedUsername);
                //String DecryptedPassword = doDecryption(obj.get("Password").toString(),BagPasswordRead);
                String DecryptedPassword = "*****";
                System.out.println(DecryptedPassword);
                if (Comment == null)
                {
                    String DecryptedComment = ""; 
                    System.out.println(DecryptedComment);
                }
                else
                {
                    String DecryptedComment = doDecryption(obj.get("Comment").toString(),BagPasswordRead);
                    System.out.println(DecryptedComment);
                }
           }
        }
        
        
    }
    
    public static void createBag() throws IOException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        FileWriter writefile = new FileWriter("keybag.txt", true);
        //writefile.write("Line|$|Service|$|URL|$|Name|$|Password|$|Comment");
        writefile.close();
    }
    
    public static String[] LineParser(String LineToParse)
    {
        return LineToParse.split("|$|");
    }
    
    public static String doEncryption(String plainText, String key) throws Exception 
    {
        byte[] clean = plainText.getBytes();

        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key.getBytes("UTF-8"));
        byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);

        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);
        
        return Base64.getEncoder().encodeToString(encryptedIVAndText);
    }
    
    public static String doDecryption(String encryptedIvTextBytes, String key) throws Exception 
    {
        int ivSize = 16;
        int keySize = 16;

        byte[] pwn = Base64.getDecoder().decode(encryptedIvTextBytes);
        
        
        byte[] iv = new byte[ivSize];
        System.arraycopy(pwn, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        int encryptedSize = pwn.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(pwn, ivSize, encryptedBytes, 0, encryptedSize);

        byte[] keyBytes = new byte[keySize];
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(key.getBytes());
        System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

        return new String(decrypted);
    }
    
    public static String[] doEncryptionOld(String Entry, String BagPassword) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {       
        byte[] EntryArray = Entry.getBytes();
        
        int SizeIV = 16;
        byte[] IV = new byte[SizeIV];
        SecureRandom RandomGenerator = new SecureRandom();
        RandomGenerator.nextBytes(IV);
        IvParameterSpec IvParamSpec = new IvParameterSpec(IV);
        
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(BagPassword.getBytes("UTF-8"));
        byte[] BagPasswordBytes = new byte[16];
        System.arraycopy(sha.digest(), 0, BagPasswordBytes, 0, BagPasswordBytes.length);
        SecretKeySpec secretKey = new SecretKeySpec(BagPasswordBytes,"AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParamSpec);
        byte[] EncryptedEntry = cipher.doFinal();
        
        String[] Output = new String[2];
        Output[0] = Base64.getEncoder().encodeToString(EncryptedEntry);
        Output[1] = Base64.getEncoder().encodeToString(IV);
        
        return Output;
    }
    
    public static String doDecryptionOld(String IV, String EncryptedEntry, String BagPassword) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
        int SizeIV = 16;
        int SizeKey = 16;
        
        byte[] BytesIV = new byte[SizeIV];
        BytesIV = Base64.getDecoder().decode(IV);
        IvParameterSpec IvParamSpec = new IvParameterSpec(BytesIV);
        
        byte[] EncryptedEntryBytes = Base64.getDecoder().decode(EncryptedEntry);
        
        byte[] KeyBytes = new byte[SizeKey];
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(BagPassword.getBytes());
        System.arraycopy(sha.digest(), 0, KeyBytes, 0, KeyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KeyBytes,"AES");
        
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, IvParamSpec);
        byte[] DecryptedEntry = cipherDecrypt.doFinal(EncryptedEntryBytes);
        
        return new String(DecryptedEntry);
    }
}
