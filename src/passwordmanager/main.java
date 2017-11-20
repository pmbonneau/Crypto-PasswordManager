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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Pierre-Marc Bonneau
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
        
        Option optDecrypt = new Option("d", "decrypt", true, "decrypt entries");
        optDecrypt.setRequired(false);
        options.addOption(optDecrypt);
        
        Option optLine = new Option("i", "line", true, "specific line");
        optLine.setRequired(false);
        options.addOption(optLine);
        
        Option optService = new Option("s", "service", true, "service which uses the password");
        optService.setRequired(false);
        options.addOption(optService);
        
        Option optAddress = new Option("u", "address", true, "service address");
        optAddress.setRequired(false);
        options.addOption(optAddress);
        
        Option optUsername = new Option("n", "username", true, "account username");
        optUsername.setOptionalArg(true);
        options.addOption(optUsername);
        
        Option optPassword = new Option("p", "password", true, "account password");
        optPassword.setOptionalArg(true);
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

        boolean UsernameSet = false;
        boolean PasswordSet = false;
        for (int i = 0; i < args.length; i++)
        {
            // Check if -n (username) arg has been set.
            if (args[i].equals("-n"))
            {
                UsernameSet = true;
            }
            
            // Check if -p (password) arg has been set.
            if (args[i].equals("-p"))
            {
                PasswordSet = true;
            }
        }
        
        String BagPasswordWrite = cmd.getOptionValue("add");
        String BagPasswordRead = cmd.getOptionValue("read");
        String Service = cmd.getOptionValue("service");
        String Address = cmd.getOptionValue("address");
        String Username = cmd.getOptionValue("username");
        String Password = cmd.getOptionValue("password");
        String Comment = cmd.getOptionValue("comment");
        String BagDecrypt = cmd.getOptionValue("decrypt");
        String Line = cmd.getOptionValue("line");
        
        // Password manager file is named keybag.txt, which stores encrypted entries.
        File KeyBagFile = new File("keybag.txt");
        
        // We create a new password manager file if it does not already exists.
        if (KeyBagFile.exists() == false)
        {
            createBag();
        }
        
        // Writing a new entry if -a (add) arg is set.
        if (BagPasswordWrite != null)
        {
            // Encrypting info
            String EncryptedService = doEncryption(Service,BagPasswordWrite);
            String EncryptedAddress = doEncryption(Address,BagPasswordWrite);
            String EncryptedUsername = doEncryption(Username,BagPasswordWrite);
            String EncryptedPass = doEncryption(Password,BagPasswordWrite);
            String EncryptedComment = "";
            if (Comment != null)
            {
                EncryptedComment = doEncryption(Comment,BagPasswordWrite);
            }
            else
            {
                EncryptedComment = doEncryption("No comment",BagPasswordWrite);
            } 

            FileWriter writefile = new FileWriter("keybag.txt", true);
            FileReader readfile = new FileReader("keybag.txt");
            Path Path = Paths.get("keybag.txt");
            
            // Adding correct line number
            LineNumberReader LineCount = new LineNumberReader(readfile);
            String ActualLineCount = Long.toString(Files.lines(Path).count());
            int integerActualLineCount = Integer.parseInt(ActualLineCount);
            
            // Creating new JSON object to store encrypted info.
            JSONObject obj = new JSONObject();
            obj.put("Line", Integer.toString(integerActualLineCount + 1));
            obj.put("Service", EncryptedService);
            obj.put("URL", EncryptedAddress);
            obj.put("Name", EncryptedUsername);
            obj.put("Password", EncryptedPass);
            obj.put("Comment", EncryptedComment);
            writefile.write(obj.toString());
            writefile.write("\r\n");
            writefile.close(); 
        }
        
        // Reading all password manager entries, but keep username and password hidden.
        // Reading from password manager if -l (read) arg is set.
        if (BagPasswordRead != null)
        {
           System.out.println("Line" + "           " + "Service" + "           " + "URL" + "           " + "Name" + "          " + "Password" + "          " + "Comment" + "           ");
           Path Path = Paths.get("keybag.txt");
           List<String> lines = Files.readAllLines(Path);
           
           JSONObject obj;
           String DecryptedLine = "";
           String DecryptedService = "";
           String DecryptedAddress = "";
           String DecryptedUsername = "";
           String DecryptedPassword = "";
           String DecryptedComment = "";
              
           // Parsing JSON entries from file and do decryption.
           for (int i = 0; i < lines.size(); i++)
           {
                obj = new JSONObject(lines.get(i));
                DecryptedLine = obj.get("Line").toString();
                DecryptedService = doDecryption(obj.get("Service").toString(),BagPasswordRead);
                DecryptedAddress = doDecryption(obj.get("URL").toString(),BagPasswordRead);
                DecryptedUsername = "*****";
                DecryptedPassword = "*****";
                DecryptedComment = doDecryption(obj.get("Comment").toString(),BagPasswordRead);
                
                // Printing lines
                System.out.println(DecryptedLine + "   " + DecryptedService + "    " + DecryptedAddress + "  " + DecryptedUsername + "   " + DecryptedPassword + "   " + DecryptedComment);
           }
        }
        
        // Reading specific password manager entries and reveal only username or only password or both.
        if (BagDecrypt != null)
        {
            System.out.println("Line" + "           " + "Service" + "           " + "URL" + "           " + "Name" + "          " + "Password" + "          " + "Comment" + "           ");
            Path Path = Paths.get("keybag.txt");
            List<String> lines = Files.readAllLines(Path);
            int LineNumber = Integer.parseInt(Line);
            
            JSONObject obj = new JSONObject(lines.get(LineNumber - 1));
            String DecryptedLine = "";
            String DecryptedService = "";
            String DecryptedAddress = "";
            String DecryptedUsername = "";
            String DecryptedPassword = "";
            String DecryptedComment = "";
            
            DecryptedLine = obj.get("Line").toString();
            DecryptedService = doDecryption(obj.get("Service").toString(),BagDecrypt);
            DecryptedAddress = doDecryption(obj.get("URL").toString(),BagDecrypt);
            
            if (UsernameSet == true && Username == null)
            {
                DecryptedUsername = doDecryption(obj.get("Name").toString(),BagDecrypt);
            }
            else
            {
                DecryptedUsername = "*****";
            }
            
            if (PasswordSet == true && Password == null)
            {
                DecryptedPassword = doDecryption(obj.get("Password").toString(),BagDecrypt);
            }
            else
            {
                DecryptedPassword = "*****";
            }
            
            DecryptedComment = doDecryption(obj.get("Comment").toString(),BagDecrypt);
            
            // Printing lines.
            System.out.println(DecryptedLine + "   " + DecryptedService + "    " + DecryptedAddress + "  " + DecryptedUsername + "   " + DecryptedPassword + "   " + DecryptedComment);
        }
    }
    
    // This method creates a new keybag.
    public static void createBag() throws IOException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        FileWriter writefile = new FileWriter("keybag.txt", true);
        writefile.close();
    }
    
    // This method encrypts a string using a key.
    // Based from https://gist.github.com/itarato/abef95871756970a9dad
    public static String doEncryption(String plainText, String key) throws Exception 
    {
        byte[] clean = plainText.getBytes();

        // Generating random IV.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Hashing the key to make it fixed size.
        MessageDigest Hash = MessageDigest.getInstance("SHA-256");
        Hash.update(key.getBytes("UTF-8"));
        byte[] KeyBytes = new byte[16];
        System.arraycopy(Hash.digest(), 0, KeyBytes, 0, KeyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KeyBytes, "AES");

        // Set cipher to use AES/CBC/PKCS5Padding.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        
        // Encrypt string.
        byte[] EncryptedString = cipher.doFinal(clean);

        // Concatenate IV and key.
        byte[] EncryptedIVAndText = new byte[ivSize + EncryptedString.length];
        System.arraycopy(iv, 0, EncryptedIVAndText, 0, ivSize);
        System.arraycopy(EncryptedString, 0, EncryptedIVAndText, ivSize, EncryptedString.length);
        
        // Return IV and key encoded into a string.
        return Base64.getEncoder().encodeToString(EncryptedIVAndText);
    }
    
    // This method decrypts a string using an IV with key.
    // Based from https://gist.github.com/itarato/abef95871756970a9dad
    public static String doDecryption(String encryptedIvTextBytes, String key) throws Exception 
    {
        int ivSize = 16;
        int keySize = 16;

        // Decoding IV and key into byte array.
        byte[] IvAndKeyArray = Base64.getDecoder().decode(encryptedIvTextBytes);
        
        // Rebuilding IvParameterSpec from IV in concatenated IV and key byte array.
        byte[] iv = new byte[ivSize];
        System.arraycopy(IvAndKeyArray, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        int EncryptedSize = IvAndKeyArray.length - ivSize;
        byte[] EncryptedBytes = new byte[EncryptedSize];
        
        // Getting key bytes from concatenated IV and key byte array.
        System.arraycopy(IvAndKeyArray, ivSize, EncryptedBytes, 0, EncryptedSize);

        // Hashing key bytes.
        byte[] KeyBytes = new byte[keySize];
        MessageDigest Hash = MessageDigest.getInstance("SHA-256");
        Hash.update(key.getBytes());
        System.arraycopy(Hash.digest(), 0, KeyBytes, 0, KeyBytes.length);
        
        // Rebuilding SecretKey from hashed key bytes.
        SecretKeySpec secretKeySpec = new SecretKeySpec(KeyBytes, "AES");

        // Set cipher to use AES/CBC/PKCS5Padding.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        
        // Decrypt string.
        byte[] Decrypted = cipherDecrypt.doFinal(EncryptedBytes);

        return new String(Decrypted);
    }
}
