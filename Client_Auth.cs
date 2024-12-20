using Newtonsoft.Json.Linq;
using System.Net;
using System.Text;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Globalization;
using System.Text.Json;
using System.Net.WebSockets;
using System.Diagnostics;
using System.Drawing;
using System.Security.AccessControl;
using System;
using System.IO;

namespace OAuth_App
{
    public class Client_Auth
    {
        public Auth_Tools AuthTools = new();
        public string access_token = string.Empty;
        public string access_token_secret = string.Empty;
        public string base_url = "api.ibkr.com/v1/api";
        public string consumer_key = string.Empty;
        public string cred_path = string.Empty;
        public string dhparam_fp = string.Empty;
        public string encryption_fp = string.Empty;
        public string live_session_token = string.Empty;
        public string oauth_callback = "localhost:5002";
        public string prepend = string.Empty;
        public string realm = string.Empty;
        public string request_token = string.Empty;
        public string signature_fp = string.Empty;
        public string verifier_token = string.Empty;

        private static HttpClientHandler clientHandler = new() { AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate };
        private static HttpClient client = new(clientHandler);

        public void RequestToken()
        {
            string endpoint = "/oauth/request_token";
            Dictionary<string, string> oauth_params = new()
            {
                { "oauth_callback", this.oauth_callback},
                { "oauth_consumer_key", consumer_key },
                { "oauth_nonce", AuthTools.DhRandomGenerator().ToString("X").ToLower() },
                { "oauth_timestamp", AuthTools.GenTimeStamp() },
                { "oauth_signature_method", "RSA-SHA256" }
            };

            string oauth_signature = AuthTools.EscapeUriDataStringRfc3986(this.CalcOauthSignature(endpoint, oauth_params));
            oauth_params.Add("oauth_signature", oauth_signature);

            string resp_content = StandardRequest(endpoint, oauth_params, HttpMethod.Post);

            // Convert our lst results to a JSON Object
            JObject resp_json = JObject.Parse(resp_content);
            this.request_token = resp_json.SelectToken("oauth_token").ToString();

        }
        public void Authorize()
        {
            string url = $"https://interactivebrokers.com/authorize?oauth_token={this.request_token}&redirect_uri=http:\\/\\/localhost:20000/";
            Console.WriteLine($"Please log in to {url} and paste the 'oauth_verifier' value here: ");
            this.verifier_token = Console.ReadLine();
            Console.WriteLine($"You wrote: {this.verifier_token}");
        }
        public void AccessToken()
        {
            string endpoint = "/oauth/access_token";
            Dictionary<string, string> oauth_params = new()
            {
                { "oauth_callback", this.oauth_callback},
                { "oauth_consumer_key", consumer_key },
                { "oauth_nonce", AuthTools.DhRandomGenerator().ToString("X").ToLower() },
                { "oauth_timestamp", AuthTools.GenTimeStamp() },
                { "oauth_signature_method", "RSA-SHA256" },
                { "oauth_token", this.request_token },
                { "oauth_verifier", this.verifier_token }
            };

            string oauth_signature = AuthTools.EscapeUriDataStringRfc3986(this.CalcOauthSignature(endpoint, oauth_params));
            oauth_params.Add("oauth_signature", oauth_signature);

            string resp_content = StandardRequest(endpoint, oauth_params, HttpMethod.Post);

            // Convert our lst results to a JSON Object
            JObject resp_json = JObject.Parse(resp_content);
            this.access_token = resp_json.SelectToken("oauth_token").ToString();
            this.access_token_secret = resp_json.SelectToken("oauth_token_secret").ToString();

            // Create the file, or overwrite if the file exists.
            using (FileStream fs = File.Create(this.cred_path))
            {
                byte[] info = new UTF8Encoding(true).GetBytes($"{{\"access_token\": {this.access_token}, \"access_token_secret\": {this.access_token_secret} }}");
                // Add some information to the file.
                fs.Write(info, 0, info.Length);
            }
        }
        public void LiveSessionToken()
        {
        // -------------------------------------------------------------------
        // Step #1: Obtaining a LST
        // -------------------------------------------------------------------
            AsnReader asn1Seq = new AsnReader(AuthTools.ConstructDerBytes(this.dhparam_fp), AsnEncodingRules.DER).ReadSequence();
            BigInteger dh_modulus = asn1Seq.ReadInteger();
            BigInteger dh_generator = asn1Seq.ReadInteger();
            BigInteger dh_random = AuthTools.DhRandomGenerator();
            BigInteger dh_challenge = BigInteger.ModPow(dh_generator, dh_random, dh_modulus);

            string endpoint = "/oauth/live_session_token";
            Dictionary<string, string> oauth_params = new()
            {
                { "oauth_callback", this.oauth_callback},
                { "oauth_consumer_key", consumer_key },
                { "oauth_nonce", AuthTools.DhRandomGenerator().ToString("X").ToLower() },
                { "oauth_timestamp", AuthTools.GenTimeStamp() },
                { "oauth_signature_method", "RSA-SHA256" },
                { "oauth_token", this.access_token },
                { "diffie_hellman_challenge", dh_challenge.ToString("X").ToLower() }
            };

            string oauth_signature = AuthTools.EscapeUriDataStringRfc3986(this.CalcOauthSignature(endpoint, oauth_params));
            oauth_params.Add("oauth_signature", oauth_signature);

            string resp_content = StandardRequest(endpoint, oauth_params, HttpMethod.Post);

            // Convert our lst results to a JSON Object
            JObject resp_json = JObject.Parse(resp_content);

            string dh_response = resp_json.SelectToken("diffie_hellman_response").ToString(); // Returned DH Response is a hex-string
            string lst_signature = resp_json.SelectToken("live_session_token_signature").ToString();
            double lst_expiration = (double)resp_json.SelectToken("live_session_token_expiration") ;

            Console.WriteLine($"The Live Session Token will expire at {AuthTools.UnixTimeStampToDateTime(lst_expiration)}");

        // -------------------------------------------------------------------
        // Step #2: Compute Live Session Token
        // -------------------------------------------------------------------
            //Generate bytestring from prepend hex str.
            byte[] prepend_bytes = Convert.FromHexString(this.prepend);

            // Convert hex string response to integer and compute K=B^a mod p.
            BigInteger a = dh_random;

            BigInteger p = dh_modulus;

            // Validate that our dh_response value has a leading sign bit, and if it's not there then be sure to add it.
            if (dh_response[0] != 0)
            {
                dh_response = "0" + dh_response;
            }

            // Convert our dh_response hex string to a biginteger. 
            BigInteger B = BigInteger.Parse(dh_response, NumberStyles.HexNumber);

            // K will be used to hash the prepend bytestring (the decrypted access token) to produce the LST.
            BigInteger K = BigInteger.ModPow(B, a, p);

            // Generate hex string representation of integer K. Be sure to strip the leading sign bit.
            string hex_str_k = K.ToString("X").ToLower(); // It must be converted to lowercase values prior to byte conversion.

            // If hex string K has odd number of chars, add a leading 0
            hex_str_k = AuthTools.CheckHexLen(hex_str_k);

            // Generate hex bytestring from hex string K.
            byte[] hex_bytes_K = Convert.FromHexString(hex_str_k);

            // Generate bytestring HMAC hash of hex prepend bytestring.
            byte[] K_hash = AuthTools.EasySha1(hex_bytes_K, prepend_bytes);

            // Convert hash to base64 to retrieve the computed live session token.
            string computed_lst = Convert.ToBase64String(K_hash);

        //-------------------------------------------------------------------
        // Step #3: Validate Live Session Token
        // ------------------------------------------------------------------
            //Generate hex - encoded str HMAC hash of consumer key bytestring.
            // Hash key is base64 - decoded LST bytestring, method is SHA1

            byte[] b64_decode_lst = Convert.FromBase64String(computed_lst);

            // Convert our consumer key str to bytes
            byte[] consumer_bytes = Encoding.UTF8.GetBytes(consumer_key);

            // Hash the SHA1 bytes against our hex bytes of K.
            byte[] hashed_consumer = AuthTools.EasySha1(b64_decode_lst, consumer_bytes);

            // Convert hash to base64 to retrieve the computed live session token.
            string hex_lst_hash = Convert.ToHexString(hashed_consumer).ToLower();

            // If our hex hash of our computed LST matches the LST signature received in response, we are successful.
            if (hex_lst_hash == lst_signature)
            {
                this.live_session_token = computed_lst;

                // Overwrite if the file exists.
                using (FileStream fs = File.Create(this.cred_path))
                {
                    byte[] info = new UTF8Encoding(true).GetBytes($"{{\"access_token\": \"{this.access_token}\", \"access_token_secret\": \"{this.access_token_secret}\", \"live_session_token\": \"{this.live_session_token}\", \"lst_expiration\": {lst_expiration} }}");
                    // Add some information to the file.
                    fs.Write(info, 0, info.Length);
                }
            }
            else
            {
                Console.WriteLine("######## LST MISMATCH! ########");
                Console.WriteLine($"Hexed LST: {hex_lst_hash} | LST Signature: {lst_signature}\n");
                
            }
        }
        private string CalcOauthSignature(string endpoint, Dictionary<string, string> oauth_params)
        {
            // Sort our oauth_params dictionary by key.
            Dictionary<string, string> sorted_params = oauth_params.OrderBy(pair => pair.Key).ToDictionary(pair => pair.Key, pair => pair.Value);
            // Combine our oauth_params into a single string for our base_string.
            string params_string = string.Join("&", sorted_params.Select(kv => $"{kv.Key}={kv.Value}"));

            if (endpoint == "/oauth/live_session_token")
            {
                this.prepend = AuthTools.GenPrepend(this.encryption_fp, this.access_token_secret);
            } else
            {
                this.prepend = "";
            }
            // Create a base string by combining the prepend, url, and params string.
            string base_string = $"{this.prepend.ToLower()}POST&{AuthTools.EscapeUriDataStringRfc3986("https://"+this.base_url+endpoint)}&{AuthTools.EscapeUriDataStringRfc3986(params_string)}";

            // Convert our new string to a bytestring 
            byte[] encoded_base_string = Encoding.UTF8.GetBytes(base_string);

            byte[] signed_hash;

            if (endpoint.Contains("/oauth"))
            {
                // Create a Sha256 Instance
                SHA256 sha256_inst = SHA256.Create();

                // Generate SHA256 hash of base string bytestring.
                byte[] sha256_hash = sha256_inst.ComputeHash(encoded_base_string);

                // Create the crypto provider for our signature
                RSACryptoServiceProvider bytes_pkcs115_signature = new()
                {
                    // Utililze a keysize of 2048 rather than the default 7168
                    KeySize = 2048
                };

                // Use our function to retrieve the object bytes
                byte[] sig_der_data = AuthTools.ConstructDerBytes(signature_fp);

                // Import the bytes object as our key
                bytes_pkcs115_signature.ImportPkcs8PrivateKey(sig_der_data, out _);

                //Generate the Pkcs115 signature key
                RSAPKCS1SignatureFormatter rsaFormatter = new(bytes_pkcs115_signature);

                rsaFormatter.SetHashAlgorithm("SHA256");

                //Receive the bytestring of our signature
                signed_hash = rsaFormatter.CreateSignature(sha256_hash);
            }
            else
            {
                // Create HMAC SHA256 object
                HMACSHA256 bytes_hmac_hash_K = new()
                {
                    // Set the HMAC key to our live_session_token
                    Key = Convert.FromBase64String(this.live_session_token)
                };

                // Hash the SHA256 bytes against our encoded bytes.
                signed_hash = bytes_hmac_hash_K.ComputeHash(encoded_base_string);
            };

            // Convert the bytestring signature to base64.
            string b64_str_pkcs115_signature = Convert.ToBase64String(signed_hash);

            return b64_str_pkcs115_signature;
        }
        public string StandardRequest(string endpoint, Dictionary<string, string>? oauth_params = null, HttpMethod? request_method = null, string req_content = "{}")
        {
            try
            {
                string request_url = "https://" + this.base_url + endpoint;

                if (oauth_params == null)
                {
                    oauth_params = new Dictionary<string, string>()
                    {
                        { "oauth_consumer_key", this.consumer_key },
                        { "oauth_nonce", AuthTools.DhRandomGenerator().ToString("X").ToLower() },
                        { "oauth_timestamp", AuthTools.GenTimeStamp() },
                        { "oauth_token", this.access_token },
                        { "oauth_signature_method", "HMAC-SHA256" }
                    };
                    string oauth_signature = AuthTools.EscapeUriDataStringRfc3986(this.CalcOauthSignature(endpoint, oauth_params));
                    oauth_params.Add("oauth_signature", oauth_signature);
                }

                request_method = request_method ?? HttpMethod.Get;

                HttpRequestMessage request = new(request_method, request_url);

                // Oauth realm param omitted from signature, added to header afterward.
                oauth_params.Add("realm", this.realm);

                // Sort our params alphabetically by key.
                Dictionary<string, string> fin_sorted_params = oauth_params.OrderBy(pair => pair.Key).ToDictionary(pair => pair.Key, pair => pair.Value);

                // Assemble oauth params into auth header value as comma-separated str.
                string oauth_header = $"OAuth " + string.Join(",", oauth_params.Select(kv => $"{kv.Key}=\"{kv.Value}\""));

                request.Headers.Add("User-Agent", "csharp/6.0");
                request.Headers.Add("Accept", "*/*");
                request.Headers.Add("Connection", "keep-alive");
                request.Headers.Add("Authorization", oauth_header);

                StringContent req_content_json = new(req_content, Encoding.UTF8, "application/json");

                request.Content = req_content_json;
                
                HttpResponseMessage response = client.SendAsync(request).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    Console.WriteLine($"Request to {request_url} failed. Received status code {(int)response.StatusCode}");

                    AuthTools.WebHeaderPrint(request, response);
                }
                else
                {
                    AuthTools.WebHeaderPrint(request, response);
                }

                // We want to return our response values so we can later work with them.
                return response.Content.ReadAsStringAsync().Result;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                Environment.Exit(1);
            }
            return string.Empty;
        }

    }
} 