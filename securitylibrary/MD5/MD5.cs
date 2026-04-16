using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.MD5
{
    public class MD5
    {

        public string GetHash(string text)
        {
            byte[] newText = Encoding.UTF8.GetBytes(text);
            uint A = 0x67452301;
            uint B = 0xefcdab89;
            uint C = 0x98badcfe;
            uint D = 0x10325476;

            // calculate the new length with padding
            var paddingLength = (56 - ((newText.Length + 1) % 64)) % 64;
            var procMessage = new byte[newText.Length + 1 + paddingLength + 8];
            Array.Copy(newText, procMessage, newText.Length);
            procMessage[newText.Length] = 0x80; // add 1
            // bit converter returns little-endian format
            byte[] lengthOfMessage = BitConverter.GetBytes(newText.Length * 8);
            // add length in bits
            Array.Copy(lengthOfMessage, 0, procMessage, procMessage.Length - 8, 4);


            for (int i = 0; i < procMessage.Length / 64; ++i)
            {
                uint[] T = new uint[16];            // copy the input to T -> hash constant table

                for (int j = 0; j < 16; ++j)
                    T[j] = BitConverter.ToUInt32(procMessage, (i * 64) + (j * 4));

                uint newA = A, newB = B, newC = C, newD = D, Result = 0, constantIndex = 0;
                for (uint k = 0; k < 64; ++k)
                {
                    if (k <= 15)
                    {
                        Result = (newB & newC) | (~newB & newD);
                        constantIndex = k;    // position of k ->p(k)
                    }
                    else if (k >= 16 && k <= 31)
                    {
                        Result = (newD & newB) | (~newD & newC);
                        constantIndex = ((5 * k) + 1) % 16;
                    }
                    else if (k >= 32 && k <= 47)
                    {
                        Result = newB ^ newC ^ newD;
                        constantIndex = ((3 * k) + 5) % 16;
                    }
                    else if (k >= 48)
                    {
                        Result = newC ^ (newB | ~newD);
                        constantIndex = (7 * k) % 16;
                    }
                    // uint totalOfResult = newB + shiftLeft((newA + Result + constantTable[k] + T[constantIndex]), shiftTable[k]);
                    uint totalOfResult = newB + (((newA + Result + constantTable[k] + T[constantIndex]) << shiftTable[k]) | ((newA + Result + constantTable[k] + T[constantIndex]) >> (32 - shiftTable[k])));

                    newA = newD;
                    newD = newC;
                    newC = newB;
                    newB = totalOfResult;
                }

                A += newA;
                B += newB;
                C += newC;
                D += newD;
            }

            return GetByteString(A) + GetByteString(B) + GetByteString(C) + GetByteString(D);
        }

        static int[] shiftTable = new int[64]
        {
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        };

        static uint[] constantTable = new uint[64]
        {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        /* public static uint shiftLeft(uint input1, int input2)
         {
             return (input1 << input2) | (input1 >> (32 - input2));
         }*/

        private static string GetByteString(uint x)
        {
            return String.Join("", BitConverter.GetBytes(x).Select(y => y.ToString("x2")));
        }

    }
}



