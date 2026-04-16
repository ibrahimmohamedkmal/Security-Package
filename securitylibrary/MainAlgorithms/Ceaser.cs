using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        private const int ALPHABET_SIZE = 26;


        public string Encrypt(string plainText, int key)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentException("Input text cannot be null or empty");
            }

            key %= ALPHABET_SIZE; // to ensure key is within [0, 25] range 
            char[] cipherText = new char[plainText.Length];

            for (int i = 0; i < plainText.Length; i++)
            {
                if (!char.IsLetter(plainText[i])) // ignore non-letter characters
                {
                    cipherText[i] = plainText[i];
                    continue;
                }

                char shiftedChar = (char)(plainText[i] + key);

                if ((char.IsLower(plainText[i]) && shiftedChar > 'z') || (char.IsUpper(plainText[i]) && shiftedChar > 'Z'))
                {
                    shiftedChar = (char)(shiftedChar - ALPHABET_SIZE); // wrap around the alphabet
                }

                cipherText[i] = shiftedChar;

            }
            return new string(cipherText);

        }

        public string Decrypt(string cipherText, int key)
        {

            if (string.IsNullOrEmpty(cipherText))
            {
                throw new ArgumentException("Input text cannot be null or empty");
            }

            key %= ALPHABET_SIZE; // to ensure key is within [0, 25] range

            char[] plainText = new char[cipherText.Length];

            for (int i = 0; i < cipherText.Length; i++)
            {
                if (!char.IsLetter(cipherText[i])) // ignore non-letter characters
                {
                    plainText[i] = cipherText[i];
                    continue;
                }

                char shiftedChar = (char)(cipherText[i] - key);

                if ((char.IsLower(cipherText[i]) && shiftedChar < 'a') || (char.IsUpper(cipherText[i]) && shiftedChar < 'A'))
                {
                    shiftedChar = (char)(shiftedChar + ALPHABET_SIZE); // wrap around the alphabet
                }

                plainText[i] = shiftedChar;
            }

            return new string(plainText);


        }

        public int Analyse(string plainText, string cipherText)
        {
            for (int i = 0; i < 26; i++)
            {
                string decrypted = Decrypt(cipherText, i);
                if (decrypted.Equals(plainText, StringComparison.InvariantCultureIgnoreCase))
                {
                    return i;
                }
            }
            return 0;


        }
    }
}
