using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace OAuth_App
{
    internal class Program
    {
        private static void WiseAuth(Client_Auth auth)
        {
            string line;
            string credential = "testcons";
            StreamReader sr = new(@"C:\Users\awise\Code\credentials.json");
            line = sr.ReadToEnd();
            JObject credentials_json = JObject.Parse(line);
            auth.consumer_key = credentials_json.SelectToken(credential).SelectToken("consumer_key").ToString();
            if (auth.consumer_key == "TESTCONS") { auth.realm = "test_realm"; }
            auth.cred_path = $"C:\\Users\\awise\\Code\\{auth.consumer_key}_tokens.json";
            try
            {
                JObject n_cred_json = JObject.Parse(File.ReadAllText(auth.cred_path));
                auth.access_token = n_cred_json.SelectToken("access_token").ToString();
                auth.access_token_secret = n_cred_json.SelectToken("access_token_secret").ToString();
                double lst_expiration = (double)n_cred_json.SelectToken("lst_expiration");
                double epoch_now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (lst_expiration <= epoch_now)
                {
                    auth.LiveSessionToken();
                }
                else
                {
                    auth.live_session_token = n_cred_json.SelectToken("live_session_token").ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Prior tokens are invalid. Generating new tokens");
                auth.dhparam_fp = credentials_json.SelectToken(credential).SelectToken("dhparam").ToString();
                auth.encryption_fp = credentials_json.SelectToken(credential).SelectToken("encryption").ToString();
                auth.signature_fp = credentials_json.SelectToken(credential).SelectToken("signature").ToString();
                auth.RequestToken();
                auth.Authorize();
                auth.AccessToken();
                auth.LiveSessionToken();
            }
            sr.Close();
        }
        static void Main(string[] args) {

            Client_Auth auth = new();
            /*
             WiseAuth is my way of reading a personal JSON file to retain credentials.
             Anyone other than Andrew Wise should define the following values for the Auth Object:
                string auth.consumer_key    => Your Consumer Key
                string auth.realm           => For TESTCONS, use "test_realm". For anything else, use "limited_poa".
                string auth.dhparam_fp      => Path to your dhparam file.
                string auth.encryption_fp   => Path to your private encryption key file.
                string auth.signature_fp    => Path to your private signature key file.
            Followed by calls to the following endpoints
                auth.RequestToken()         => Generate a Request Token, step one of the Third Party Workflow.
                auth.Authorize()            => Authorize the Consumer Key for your account.
                auth.AccessToken()          => Generate an access token and access token secret.
                auth.LiveSessionToken()     => Generate a Live Session Token for the current session. 
            */
            WiseAuth(auth);
            try
            {
                auth.StandardRequest(
                    endpoint: "/iserver/auth/ssodh/init",
                    request_method: HttpMethod.Post,
                    req_content: "{\"compete\":true, \"publish\":true}"
                );
                // The system needs a moment to spin up before making requests.
                System.Threading.Thread.Sleep(1000);

                auth.StandardRequest(
                    endpoint: "/iserver/accounts"
                );

                auth.StandardRequest(
                    endpoint: "/hmds/auth/init",
                    request_method: HttpMethod.Post
                );

                auth.StandardRequest(
                    endpoint: "/hmds/history?conid=265598&period=5d&bar=1d",
                    request_method: HttpMethod.Post
                );

            }

            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }
    }
}
