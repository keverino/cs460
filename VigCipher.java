//Name: Kevin Lee
//Course: CS 460 - Secure Communication
//Assignment 1: Vigenere's cipher with GUI

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

class VigCipher implements ActionListener
{
	private JFrame jfrm;
 	private JTextArea textArea;
 	private String cipherText, decryptedText;
//----------------------------------------------------------------------------------------------------
	public static void main(String args[]) { new VigCipher(); }
//----------------------------------------------------------------------------------------------------
   public VigCipher()
	{
		// Create a new JFrame container with specified settings.
      jfrm = new JFrame("Vigenère Cipher");
      jfrm.setLayout(new BorderLayout());
      jfrm.setSize(600, 450);
      jfrm.setLocationRelativeTo(null);
      jfrm.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
      jfrm.setResizable(false);

      // Create a text area within a scrollpane
      textArea = new JTextArea(19, 46);
      JScrollPane scrollPane = new JScrollPane(textArea);
      textArea.setEditable(false);
      Font font = new Font("Arial", Font.PLAIN, 14);
		textArea.setFont(font);

		// Create buttons and action listeners
		JButton clearButton = new JButton("Clear");
		JButton encryptButton = new JButton("Encrypt");
		JButton decryptButton = new JButton("Decrypt");
		clearButton.addActionListener(this);
		encryptButton.addActionListener(this);
		decryptButton.addActionListener(this);
		
      // Add objects to panel
      JPanel panel = new JPanel(new FlowLayout());
      panel.add(encryptButton);
      panel.add(decryptButton);
      panel.add(clearButton);
      panel.add(textArea);
      panel.add(new JLabel("<html>Author: Kevin Lee<br>BroncoID: 006997497</html>"));

      // Add panel to the frame and display frame
      jfrm.add(panel);
      jfrm.setVisible(true);
	}// end of VigCipher()
//----------------------------------------------------------------------------------------------------
	public String encrypt(String text, String key) 
	{
      String encrypted = "";
      text = text.toUpperCase();
      for (int i = 0, j = 0; i < text.length(); i++) 
      {
         char c = text.charAt(i);
         if (c == (' ')) encrypted += (char) '$';
         if (c < 'A' || c > 'Z') continue;
         encrypted += (char) ( (c + key.charAt(j) - 2 * 'A') % 26 + 'A');
         j = ++j % key.length();
      }
      return encrypted;
   }// end of encrypt()
//----------------------------------------------------------------------------------------------------
   public String decrypt(String text, String key) 
   {
      String decrypted = "";
      text = text.toUpperCase();
      for (int i = 0, j = 0; i < text.length(); i++) 
      {
         char c = text.charAt(i);
         if (c == ('$')) decrypted += (char) ' ';
         if (c < 'A' || c > 'Z') continue;
         decrypted += (char) ( (c - key.charAt(j) + 26) % 26 + 'A');
         j = ++j % key.length();
      }
      return decrypted;
   }// end of decrypt()
//----------------------------------------------------------------------------------------------------
   public void actionPerformed(ActionEvent ae)
   {
      try
     	{
         // if Clear button is pressed
         if(ae.getActionCommand().equals("Clear")) 
         {
        	   textArea.setText("");
        	   cipherText = "";
        	   decryptedText = "";
         }
         // if Encrypt button is pressed
         else if(ae.getActionCommand().equals("Encrypt"))
         {
            // get plaintext from user
				String plaintextInput = JOptionPane.showInputDialog("Enter something to encrypt.");
				plaintextInput = plaintextInput.toUpperCase();
				textArea.append("Plaintext:\t" + plaintextInput + "\n");

				// get key from user
				String keyInput = JOptionPane.showInputDialog("Enter a key.");
				keyInput = keyInput.toUpperCase();
				textArea.append("Key:\t" + keyInput + "\n\n");

				// encryption
				textArea.append("Encrypting the plaintext..." + "\n");
				cipherText = encrypt(plaintextInput, keyInput);
				textArea.append("Ciphertext:\t" + cipherText + "\n\n");
         }
         // if Decrypt button is pressed
         else if(ae.getActionCommand().equals("Decrypt"))
         {
        	   // get key from user
				String keyInput = JOptionPane.showInputDialog("Enter the key used to encrypt the text.");
				keyInput = keyInput.toUpperCase();
				textArea.append("Key:\t" + keyInput + "\n\n");

				// decryption
				textArea.append("Decrypting the ciphertext..." + "\n");
				decryptedText = decrypt(cipherText, keyInput);
			   textArea.append("Plaintext:\t" + decryptedText + "\n\n");
         }
      }// end try
   	catch (Exception e){}
   }// end of actionPerformed()
//----------------------------------------------------------------------------------------------------
}//end of VigCipher class