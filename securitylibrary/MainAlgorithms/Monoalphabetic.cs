using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            string cipherTextLower = cipherText.ToLower();
            string plainTextLower = plainText.ToLower();
            var key = new char[26];
            var plainAlphabet = new char[26];
            var usedValues = new bool[26];

            char currentChar = 'a';
            for (int i = 0; i < 26; i++)
            {
                plainAlphabet[i] = currentChar;
                currentChar++;
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                char plainChar = plainTextLower[i];
                for (int j = 0; j < 26; j++)
                {
                    if (plainChar == plainAlphabet[j])
                    {
                        key[j] = cipherTextLower[i];
                        break;
                    }
                }
            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                char cipherChar = cipherTextLower[i];
                for (int j = 0; j < 26; j++)
                {
                    if (cipherChar == plainAlphabet[j])
                    {
                        usedValues[j] = true;
                        break;
                    }
                }
            }

            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == '\0')
                {
                    for (int j = 0; j < usedValues.Length; j++)
                    {
                        if (!usedValues[j])
                        {
                            key[i] = plainAlphabet[j];
                            usedValues[j] = true;
                            break;
                        }
                    }
                }
            }

            return new string(key);

        }

        public string Decrypt(string cipherText, string key)
        {

            if (key.Length != 26)
            {
                throw new ArgumentException("Key must be exactly 26 characters long.");
            }
            cipherText = cipherText.ToLower();
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            string plaintext = "";
            int keynum = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                keynum = key.IndexOf(cipherText[i]);
                plaintext += alphabet[keynum];
            }
            return plaintext.ToUpper();
        }

        public string Encrypt(string plainText, string key)
        {
            if (key.Length != 26)
            {
                throw new ArgumentException("Key must be exactly 26 characters long.");
            }

            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            string ciphertext = "";
            int keynum = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                keynum = alphabet.IndexOf(plainText[i]);
                ciphertext += key[keynum];
            }
            return ciphertext;

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipherText)
        {
            // Define the most frequent characters in the English language
            string mostFrequentChars = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();

            // Convert the cipher text to lower case
            cipherText = cipherText.ToLower();

            // Get the length of the cipher text
            int cipherTextLength = cipherText.Length;

            // Get the distinct characters in the cipher text
            string distinctChars = new String(cipherText.Distinct().ToArray());
            int distinctCharsLength = distinctChars.Length;

            // Create an array to store the frequency of each distinct character
            int[] charFrequencies = new int[distinctCharsLength];

            // Create a list to store key-value pairs of characters and their frequencies
            List<KeyValuePair<char, int>> charFrequencyList = new List<KeyValuePair<char, int>>();

            // Count the frequency of each character in the cipher text
            for (int i = 0; i < cipherTextLength; i++)
            {
                for (int j = 0; j < distinctCharsLength; j++)
                {
                    if (String.Equals(cipherText[i], distinctChars[j]))
                        charFrequencies[j]++;
                }
            }

            // Add each character and its frequency to the list as a key-value pair
            for (int counter = 0; counter < distinctCharsLength; counter++)
                charFrequencyList.Add(new KeyValuePair<char, int>(distinctChars[counter], charFrequencies[counter]));

            // Sort the list by frequency in ascending order
            charFrequencyList = charFrequencyList.OrderBy(x => x.Value).ToList();

            string key = "";
            int position;
            for (int i = 0; i < cipherTextLength; i++)
            {
                position = charFrequencyList.FindIndex(x => x.Key == cipherText[i]);
                key += mostFrequentChars[25 - position];
            }

            return key;
        }
    }
}
