using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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
            var KEY = "";
            int j = 0;
            for (int i = 0; i < plain.Length; i++)
            {
                int plain_index = char.ToUpper(plain[i]) - 65;//index == 1

                for (int m = 0; m < 26; m++)
                {
                    if (char.ToLower(table[plain_index, m]) == cipher[i])
                    {
                        KEY += char.ConvertFromUtf32(m + 65);

                    }
                }
                j++;
            }
            var zz = "";
            int mn = 0;

            for (int k = 0; k < KEY.Length; k++)
            {
                if (KEY[KEY.Length - (k + 1)] == KEY[0])
                {
                    if (KEY[KEY.Length - (k)] == KEY[1])
                    {
                        mn += 1;
                    }

                }
            }
            decimal ll = KEY.Length / mn;
            ll = Math.Ceiling(ll);
            for (int i = 0; i < ll; i++)
            {
                zz += KEY[i];
            }

            if (KEY[zz.Length] != KEY[0])
            {

                for (int i = zz.Length; i < KEY.Length; i++)
                {
                    if (KEY[i] != KEY[0])
                    {
                        zz += KEY[i];
                    }
                    else
                    {
                        break;
                    }
                }
            }
            return zz.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            var cipher = cipherText;
            var plain = "";
            var KEY = key;
            int j = 0;
            int key_index = 0;

            for (int i = 0; i < cipher.Length; i++)
            {
                //repeating key 
                if (cipher.Length > KEY.Length)
                {
                    if (j == KEY.Length)
                    {
                        j = 0;
                    }
                }
                key_index = char.ToUpper(KEY[j]) - 65;//index == 1

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
            var cipher = "";
            var plain = plainText;
            var Key = key;
            //throw new NotImplementedException();
            int j = 0;
            for (int i = 0; i < plain.Length; i++)
            {
                //repeating key 
                if (plain.Length > key.Length)
                {
                    if (j == key.Length)
                    {
                        j = 0;
                    }
                }
                int plain_index = char.ToUpper(plain[i]) - 65;//index == 1
                int key_index = char.ToUpper(Key[j]) - 65;//index == 1

                cipher += Convert.ToString(table[plain_index, key_index]);
                j++;
            }

            return cipher;
        }
    }
}