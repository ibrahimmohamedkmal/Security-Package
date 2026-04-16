using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {


        public string Encrypthex(string plainTextHex, string keyHex)
        {
            string plainText = HexToString(plainTextHex.Substring(2, plainTextHex.Length - 2));
            string key = HexToString(keyHex.Substring(2, keyHex.Length - 2));
            char[] pl = plainText.ToCharArray();
            string ci = "";
            char[] s = Initials(key);
            char[] sub_keys = key_stream(s, pl.Length);
            for (int i = 0; i < sub_keys.Length; i++)
            {
                ci += (char)(pl[i] ^ sub_keys[i]);
            }
            string x = "0x" + StringToHex(ci);
            return x;
        }
        public string Encryp(string plainText, string key)
        {
            char[] pl = plainText.ToCharArray();
            string ci = "";
            char[] s = Initials(key);
            char[] sub_keys = key_stream(s, pl.Length);
            for (int i = 0; i < sub_keys.Length; i++)
            {
                ci += (char)(pl[i] ^ sub_keys[i]);
            }
            return ci;
        }

        public string HexToString(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            string outputString = Encoding.Default.GetString(bytes);
            return outputString;
        }

        public string StringToHex(string str)
        {
            byte[] bytes = Encoding.Default.GetBytes(str);
            string hexString = BitConverter.ToString(bytes).Replace("-", "");
            return hexString;
        }


        public override string Decrypt(string cipherText, string key)
        {
            if (cipherText.StartsWith("0x"))
            {
                return Encrypthex(cipherText, key);
            }
            else
            {
                return Encryp(cipherText, key);
            }
        }


        public override string Encrypt(string plainText, string key)
        {
            if (plainText.StartsWith("0x"))
            {
                return Encrypthex(plainText, key);
            }
            else
            {
                return Encryp(plainText, key);
            }

        }


        public char[] Initials(string key)
        {
            char[] keychars = key.ToCharArray();
            char[] s = new char[256];
            char[] t = new char[256];
            for (int i = 0; i < 255; i++)
            {
                s[i] = (char)i;
                t[i] = keychars[i % keychars.Length];
            }
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + t[i]) % 256;
                swap(s, i, j);
            }
            return s;
        }

        public void swap(char[] arr, int i, int j)
        {
            char temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;
        }

        public char[] key_stream(char[] s, int text_lenth)
        {
            int i = 0;
            int j = 0;
            char[] sub_key = new char[text_lenth];
            for (int k = 0; k < text_lenth; k++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                swap(s, i, j);
                sub_key[k] = s[(s[i] + s[j]) % 256];

            }
            return sub_key;

        }
    }
}
