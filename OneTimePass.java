import java.io.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class OneTimePass 
{
   static String actionInput, username, password, hashedPassword;
   static boolean authenticated, newFile = false;
   static BufferedReader inputReader = new BufferedReader(new InputStreamReader(System.in));
   static File file = new File("users.bin");
   static AESEncryption aes = new AESEncryption();
//------------------------------------------------------------------------------------------------------
   public static void main(String[] args) throws Exception { mainMenu(); }
//------------------------------------------------------------------------------------------------------
   public static void mainMenu() throws Exception
   {
      clearConsole();
      System.out.println(":::::::: S/KEY One Time Password ::::::::");
      System.out.println("Please choose an action.");
      System.out.println("(1) Create Account");
      System.out.println("(2) Login");
      actionInput = inputReader.readLine();

      if(actionInput.equals("1")) createAccount();
      if(actionInput.equals("2")) login();
   }
//------------------------------------------------------------------------------------------------------
   public static void reset()
   {
      actionInput = "";
      username = "";
      password = "";
      hashedPassword = "";
      newFile = false;
      authenticated = false;
   }
//------------------------------------------------------------------------------------------------------
   public static void clearConsole() { System.out.print("\033[H\033[2J"); }
//------------------------------------------------------------------------------------------------------
   public static void createAccount() throws Exception
   {
      checkForFile();
      if(newFile == false) aes.decrypt(file); // decrypt the user.bin file so the program can access it

      clearConsole();
      System.out.println(":::::::: S/KEY One Time Password ::::::::");
      System.out.println("-------- Create Account --------");
      System.out.print("Please choose your username: ");
      username = inputReader.readLine();
      System.out.print("Please choose your password: ");
      password = inputReader.readLine();

      hash();
      addUser();
      reset();
      aes.encrypt(file); // encrypt the file after accessing

      System.out.println("Hit the 'Enter' key to return to the main menu.");
      inputReader.readLine();
      mainMenu();
   }
//------------------------------------------------------------------------------------------------------
   public static void login() throws Exception
   {
      checkForFile();
      if(newFile == false) aes.decrypt(file); // decrypt the user.bin file so the program can access it

      clearConsole();
      System.out.println(":::::::: S/KEY One Time Password ::::::::");
      System.out.println("-------- Login --------");
      System.out.print("Username: ");
      username = inputReader.readLine();
      System.out.print("Password: ");
      password = inputReader.readLine();

      clearConsole();
      hash();
      verifyAccount();
      reset();
      aes.encrypt(file); // encrypt the file after accessing

      System.out.println("Hit the 'Enter' key to return to the main menu.");
      inputReader.readLine();
      mainMenu();
   }
//------------------------------------------------------------------------------------------------------
   public static void verifyAccount() throws Exception
   {
      BufferedReader br = new BufferedReader(new FileReader(file));
      String line;

      while ((line = br.readLine()) != null) 
      {
         // if username matches file and if hashed password matches file
         if(line.contains(username))
         {
            if(line.contains(hashedPassword)) authenticated = true; 
         }
         else { authenticated = false; } // if username & password combination does not match
      }
      br.close();

      System.out.println(":::::::: S/KEY One Time Password ::::::::");
      if(authenticated == true && accountExists() == true) System.out.println("\nAUTHENTICATED: Welcome " + username + "!");
      if(authenticated == false && accountExists() == true) System.out.println("\nERROR: Username & password combination does not match.");
      if(accountExists() == false) System.out.println("\nERROR: Username '" + username + "'" + " does not exist.");
   }
//------------------------------------------------------------------------------------------------------
   public static boolean accountExists() throws Exception
   {
      BufferedReader br = new BufferedReader(new FileReader(file));
      String line;
      boolean accountExists = false;

      while ((line = br.readLine()) != null) 
      {
         // if the username matches file
         if(line.contains(username)) accountExists = true;
      }
      br.close();

      return accountExists;
   }
//------------------------------------------------------------------------------------------------------
   public static void checkForFile() throws Exception
   {
      if(!file.exists())
      { 
         // create user.bin file
         ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file));
         newFile = true;
      }
   }
//------------------------------------------------------------------------------------------------------
   public static void addUser() throws Exception
   {
      if(accountExists() == true) 
      { 
         System.out.println("\nERROR: " + username + " is already in use."); 
      }

      // if the account does not exist
      else
      {
         try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(file, true)))) 
         {
            out.println(username + ":" + hashedPassword);
         } 
         catch (IOException e) { }
         System.out.println("Account created.");
      }
   }
//------------------------------------------------------------------------------------------------------
   public static void hash()
   {
      try 
      {
         // Hash using SHA-1
         MessageDigest md = MessageDigest.getInstance("SHA-1");
         String input = password;

         // Hash password 100 times
         md.update(input.getBytes()); 
         byte[] output = md.digest();
         for(int i = 0; i < 99; i++)
         {
            md.update(output);
            output = md.digest();
         }

         // convert bytes to hex
         bytesToHex(output);
      } catch (Exception e) { System.out.println("Exception: " + e); }
   }
//------------------------------------------------------------------------------------------------------
  public static String bytesToHex(byte[] b) 
  {
      char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

      StringBuffer buf = new StringBuffer();
      for (int j=0; j<b.length; j++) 
      {
         buf.append(hexDigit[(b[j] >> 4) & 0x0f]);
         buf.append(hexDigit[b[j] & 0x0f]);
      }

      hashedPassword = buf.toString();
      return hashedPassword;        
  }
//------------------------------------------------------------------------------------------------------
}// end OneTimePass class
//------------------------------------------------------------------------------------------------------
class AESEncryption
{
   private static final String ALGORITHM = "AES";
   private static final String TRANSFORMATION = "AES";
   private static String keyName = "key.bin";
//------------------------------------------------------------------------------------------------------
   public static void encrypt(File fileName) throws Exception
   {
      Key newKey = KeyGenerator.getInstance("AES").generateKey();

      try
      {
         // save the key
         ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(keyName));
         oos.writeObject(newKey);
         oos.close();
      }
      catch (IOException e) { System.out.println("Error trying to save the AES key"); }

      doCrypto(Cipher.ENCRYPT_MODE, newKey, fileName);
   }
//------------------------------------------------------------------------------------------------------
   public static void decrypt(File fileName) throws Exception
   {

      // load the key
      File oldKeyFile = new File(keyName);
      ObjectInputStream ois = new ObjectInputStream(new FileInputStream(oldKeyFile));
      Key oldKey = (Key) ois.readObject();
      ois.close();

      doCrypto(Cipher.DECRYPT_MODE, oldKey, fileName);
   }
//------------------------------------------------------------------------------------------------------
   private static void doCrypto(int cipherMode, Key secretKey, File fileName) throws Exception
   {
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(cipherMode, secretKey);
      
      // read the file
      FileInputStream inputStream = new FileInputStream(fileName);
      byte[] inputBytes = new byte[(int) fileName.length()];
      inputStream.read(inputBytes);
             
      // encrypt or decrypt
      byte[] outputBytes = cipher.doFinal(inputBytes);
             
      // save the output
      FileOutputStream outputStream = new FileOutputStream(fileName);
      outputStream.write(outputBytes);
             
      inputStream.close();
      outputStream.close();
   }
//------------------------------------------------------------------------------------------------------
}// end of AESEncryption class
//----------------------------------------------------------------------------------------------------