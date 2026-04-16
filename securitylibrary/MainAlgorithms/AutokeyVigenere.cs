using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        // the table 
        char[,] table = {  {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'},
                                 {'b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a'},
                                 {'c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b'},
                                 {'d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c'},
                                 {'e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d'},
                                 {'f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e'},
                                 {'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f'},
                                 {'h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g'},
                                 {'i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h'},
                                 {'j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i'},
                                 {'k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j'},
                                 {'l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k'},
                                 {'m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l'},
                                 {'n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m'},
                                 {'o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n'},
                                 {'p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o'},
                                 {'q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'},
                                 {'r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q'},
                                 {'s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r'},
                                 {'t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s'},
                                 {'u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t'},
                                 {'v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u'},
                                 {'w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v'},
                                 {'x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w'},
                                 {'y','z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x'},
                                 {'z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y'}
                                  };

        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            var cipher = cipherText.ToLower();
            var plain = plainText.ToLower();
            var Key1 = "";
            var zz = "";
            int plain_index = 0;

            for (int i = 0; i < cipher.Length; i++)
            {
                plain_index = char.ToUpper(plain[i]) - 65;//index == 0

                for (int m = 0; m < 26; m++)
                {
                    if (char.ToLower(table[plain_index, m]) == cipher[i])
                    {
                        Key1 += char.ConvertFromUtf32(m + 65);
                    }
                }
            }
            int tst = 0;
            int count = 1;

            for (int i = plain.Length - 1; i >= 0; i--)
            {
                if (char.ToLower(plain[i]) == char.ToLower(Key1[Key1.Length - count]))
                {
                    count++;
                    if (count - 1 == (Key1.Length - tst))
                    {
                        break;
                    }

                }
                else
                {
                    tst++;
                }

            }
            for (int i = 0; i < tst; i++)
            {
                zz += Key1[i];
            }
            return zz.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            var cipher = cipherText;
            var plain = "";
            var Key1 = key;
            int j = 0;
            int k = 0;
            int key_index = 0;

            for (int i = 0; i < cipher.Length; i++)
            {
                if (i < Key1.Length)
                {
                    key_index = char.ToUpper(Key1[i]) - 65;//index == 0
                    j++;
                }
                else if (i >= Key1.Length)
                {
                    j = k;
                    key_index = char.ToUpper(plain[i - Key1.Length]) - 65;//index == 0
                    k++;
                }

                for (int m = 0; m < 26; m++)
                {
                    if (char.ToUpper(table[m, key_index]) == cipher[i])
                    {
                        plain += char.ConvertFromUtf32(m + 65);
                    }
                }
                j++;
            }
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            var cipher = "";
            var plain = plainText;
            var Key = key;
            //throw new NotImplementedException();
            int j = 0;
            int k = 0;
            int key_index = 0;
            for (int i = 0; i < plain.Length; i++)
            {
                int plain_index = char.ToUpper(plain[i]) - 65;//index == 0                                    
                if (i < Key.Length)
                {
                    key_index = char.ToUpper(Key[j]) - 65;//index == 0
                    j++;
                }
                else if (i >= Key.Length)
                {
                    j = k;
                    key_index = char.ToUpper(plain[i - Key.Length]) - 65;//index == 0
                    k++;
                }
                cipher += table[plain_index, key_index];
            }
            return cipher;
        }
    }
}
