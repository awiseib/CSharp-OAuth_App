using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OAuth_App
{
    public class Auth_Tools
    {
        public string EscapeUriDataStringRfc3986(string value)
        {
            // Replace the default RFC 2396 supported through C# with its RFC 3986 equivalent

            string[] UriRfc3986CharsToEscape = new[] { "!", "*", "'", "(", ")" };

            StringBuilder escaped = new(Uri.EscapeDataString(value));

            // Upgrade the escaping to RFC 3986, if necessary.
            for (int i = 0; i < UriRfc3986CharsToEscape.Length; i++)
            {
                escaped.Replace(UriRfc3986CharsToEscape[i], Uri.HexEscape(UriRfc3986CharsToEscape[i][0]));
            }

            // Return the fully-RFC3986-escaped string.
            return escaped.ToString();
        }

        public byte[] EasySha1(byte[] intended_key, byte[] intended_msg)
        {
            // Create HMAC SHA1 object
            HMACSHA1 bytes_hmac_hash_K = new()
            {
                // Set the HMAC key to our passed intended_key byte array
                Key = intended_key
            };
            // Hash the SHA1 bytes of our key against the msg content.
            byte[] K_hash = bytes_hmac_hash_K.ComputeHash(intended_msg);

            return K_hash;
        }

        public byte[] ConstructDerBytes(string pem_fp)
        {
            // Read the content of our DH Param PEM file and assign the content to a String
            StreamReader sr = new(pem_fp);
            string reader = sr.ReadToEnd();
            sr.Close();

            // Find the pem field content from the StreamReader string
            PemFields pem_fields = PemEncoding.Find(reader);

            // Convert the pem base 64 string content into a byte array for use in our import
            byte[] der_data = Convert.FromBase64String(reader[pem_fields.Base64Data]);
            return der_data;

        }

        public string CheckHexLen(string hex_str_k)
        {
            // Validate our hexidecimal string value.
            if (hex_str_k.Length % 2 != 0)
            {
                // Set the lead byte to 0 for a positive sign bit.
                hex_str_k = "0" + hex_str_k;
                return hex_str_k;
            }
            else
            {
                // If we have an already even hexidecimal K value, we simply return the existing value.
                return hex_str_k;
            }
        }

        public BigInteger DhRandomGenerator()
        {
            // Create a Random object, and then retrieve any random positive integer value.
            Random random = new();

            return random.Next(1, int.MaxValue);
        }

        public string GenTimeStamp()
        {
            // Interactive Brokers requires a 10 digit Unix timestamp value.
            // Values beyond 10 digits will result in an error.
            string timestamp = DateTimeOffset.Now.ToUnixTimeMilliseconds().ToString();
            timestamp = timestamp.Substring(0, timestamp.Length - 3);
            return timestamp;
        }

        public string GenPrepend(string encryption_fp, string access_token_secret)
        {
            // Create the crypto provider 
            RSACryptoServiceProvider bytes_decrypted_secret = new()
            {
                // Utililze a keysize of 2048 rather than the default 7168
                KeySize = 2048
            };

            // Use our function to retrieve the object bytes
            byte[] enc_der_data = ConstructDerBytes(encryption_fp);

            // Import the bytes object as our key
            bytes_decrypted_secret.ImportPkcs8PrivateKey(enc_der_data, out _);

            // Encode the access token secret as an ASCII bytes object
            byte[] encryptedSecret = Convert.FromBase64String(access_token_secret);

            // Decrypt our secret bytes with the encryption key
            byte[] raw_prepend = bytes_decrypted_secret.Decrypt(encryptedSecret, RSAEncryptionPadding.Pkcs1);

            // Convert our bytestring to a hexadecimal string
            string prepend = Convert.ToHexString(raw_prepend).ToLower();

            return prepend;
        }
        public DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTime = dateTime.AddSeconds(unixTimeStamp/1000).ToLocalTime();
            return dateTime;
        }
        public async Task<string> WebHeaderPrint(HttpRequestMessage request, HttpResponseMessage response)
        {
            // Print out the request and response content of our web requests to capture headers.
            await Console.Out.WriteLineAsync("########## Request ###########");
            await Console.Out.WriteLineAsync($"{request.Method} {request.RequestUri}");
            await Console.Out.WriteLineAsync(request.Headers.ToString());
            if (request.Content != null)
            {
                await Console.Out.WriteLineAsync(await request.Content.ReadAsStringAsync());
            }
            await Console.Out.WriteLineAsync("\n########## Response ###########");
            await Console.Out.WriteLineAsync($"{(int)response.StatusCode} {response.StatusCode.ToString()}");
            await Console.Out.WriteLineAsync(await response.Content.ReadAsStringAsync());
            await Console.Out.WriteLineAsync("----------------------------\n");

            return response.Content.ReadAsStringAsync().Result;
        }
    }
}