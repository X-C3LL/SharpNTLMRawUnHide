using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpNTLMRawUnhide
{
    class Program
    {
        static byte[] ntlmssp_sig = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 };
        static byte[] ntlmssp_type_2 = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00 };
        static byte[] ntlmssp_type_3 = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00 };
        static byte[] server_challenge = new byte[8];


        // https://stackoverflow.com/questions/283456/byte-array-pattern-search
        static int Search(byte[] src, byte[] pattern, int begin, int stop)
        {
            int maxFirstCharSlot = stop;
            for (int i = begin; i < maxFirstCharSlot; i++)
            {
                if (src[i] != pattern[0]) // compare only first byte
                    continue;

                // found a match on first byte, now try to match rest of the pattern
                for (int j = pattern.Length - 1; j >= 1; j--)
                {
                    if (src[i + j] != pattern[j]) break;
                    if (j == 1) return i;
                }
            }
            return -1;
        }
        // https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }
        static string retrieveData(byte[] content, int start, int position)
        {
            byte[] data_length_raw = new byte[4];
            Array.Copy(content, start + position, data_length_raw, 0, 2);
            int data_length = BitConverter.ToInt32(data_length_raw, 0);
            byte[] data_offset_raw = new byte[4];
            Array.Copy(content, start + position + 4, data_offset_raw, 0, 4);
            int data_offset = BitConverter.ToInt32(data_offset_raw, 0);
            byte[] data = new byte[data_length];
            Array.Copy(content, start + data_offset, data, 0, data_length);
            string dataString = System.Text.Encoding.Unicode.GetString(data);
            return dataString;
        }
        static void Main(string[] args)
        {
            Console.WriteLine("\t\tSharpNTLMRawUnhide - @TheXC3LL\n\n");
            string input = args[0];
            FileStream fs = File.Open(input, FileMode.Open);
            var fileInfo = new FileInfo(input);
            byte[] raw = new byte[fileInfo.Length];
            fs.Read(raw, 0, (int)fileInfo.Length);
            fs.Close();
            int offset = 0;
            while (offset != -1)
            {
                int tmp;
                if (offset != 0)
                {
                    offset += ntlmssp_sig.Length;
                }
                offset = Search(raw, ntlmssp_sig, offset, raw.Length);
                if (offset == -1)
                {
                    break;
                }
                tmp = Search(raw, ntlmssp_type_2, offset, offset + ntlmssp_type_2.Length);
                if (tmp > -1)
                {
                    Array.Copy(raw, offset + 24, server_challenge, 0, 8);
                }
                
                tmp = Search(raw, ntlmssp_type_3, offset, offset + ntlmssp_type_3.Length);
                if (tmp > -1)
                {
                    Console.WriteLine("\n[+] New NTLMSSP Message Type 3 found!");

                    string domain = retrieveData(raw, offset, 28);
                    Console.WriteLine("\t[*] Domain: {0}", domain);

                    string username = retrieveData(raw, offset, 36);
                    Console.WriteLine("\t[*] Username: {0}", username);

                    string workstation = retrieveData(raw, offset, 44);
                    Console.WriteLine("\t[*] Workstation: {0}", workstation);

                    byte[] ntlm_length_raw = new byte[4];
                    Array.Copy(raw, offset + 20, ntlm_length_raw, 0, 2);
                    int ntlm_length = BitConverter.ToInt32(ntlm_length_raw, 0);
                    byte[] ntlm_offset_raw = new byte[4];
                    Array.Copy(raw, offset + 20 + 4, ntlm_offset_raw, 0, 4);
                    int ntlm_offset = BitConverter.ToInt32(ntlm_offset_raw, 0);
                    byte[] ntproof = new byte[16];
                    Array.Copy(raw, offset + ntlm_offset, ntproof, 0, 16);
                    byte[] ntlmv2_response = new byte[ntlm_length - 16];
                    Array.Copy(raw, offset + ntlm_offset + 16, ntlmv2_response, 0, ntlm_length - 16);
                    if (server_challenge[0] != '\0')
                    {
                        Console.WriteLine("\t[*] Hash:\n{0}::{1}:{2}:{3}:{4}", username, domain, ByteArrayToString(server_challenge), ByteArrayToString(ntproof), ByteArrayToString(ntlmv2_response));
                        Array.Clear(server_challenge, 0, server_challenge.Length);
                    }
                }
            }

        }
    }
}
