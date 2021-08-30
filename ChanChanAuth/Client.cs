using System;
using System.Linq;
using Leaf.xNet;
using Fernet;
using Newtonsoft.Json.Linq;

namespace ChanChanAuth
{
    public class Client
    {
        [Serializable]
        class InvalidSecret : Exception
        {
            public InvalidSecret()
            {
            }

            public InvalidSecret(string message)
                : base(message)
            {
            }

            public InvalidSecret(string message, Exception inner)
                : base(message, inner)
            {
            }
        }
        [Serializable]
        class InvalidKey : Exception
        {
            public InvalidKey()
            {
            }

            public InvalidKey(string message)
                : base(message)
            {
            }

            public InvalidKey(string message, Exception inner)
                : base(message, inner)
            {
            }
        }
        [Serializable]
        class InvalidAID : Exception
        {
            public InvalidAID()
            {
            }

            public InvalidAID(string message)
                : base(message)
            {
            }

            public InvalidAID(string message, Exception inner)
                : base(message, inner)
            {
            }
        }
        [Serializable]
        class EmptyRequiredInfo : Exception
        {
            public EmptyRequiredInfo()
            {
            }

            public EmptyRequiredInfo(string message)
                : base(message)
            {
            }

            public EmptyRequiredInfo(string message, Exception inner)
                : base(message, inner)
            {
            }
        }
        [Serializable]
        class UnknownError : Exception
        {
            public UnknownError()
            {
            }

            public UnknownError(string message)
                : base(message)
            {
            }

            public UnknownError(string message, Exception inner)
                : base(message, inner)
            {
            }
        }
        [Serializable]
        class InvaldLength : Exception
        {
            public InvaldLength()
            {
            }

            public InvaldLength(string message)
                : base(message)
            {
            }

            public InvaldLength(string message, Exception inner)
                : base(message, inner)
            {
            }
        }

        private static string ClientKey;
        private static byte[] ClientSecret;
        private static string ClientAid;
        
        /// <summary>
        /// Initiliaze Client before using.
        /// This is required since this stores the Key, AID, and Secret
        /// </summary>
        /// <param name="clientKey">The Key that's given to you</param>
        /// <param name="clientSecret">The Secret that's given to you</param>
        /// <param name="clientAid">The AID that's given to you</param>
        /// <example>
        /// ChanChanAuth.Client.Init(clientKey: "client-key-here", clientSecret: "client-Secret-(Base64)=", clientAid: "client-aid"");
        /// </example>
        public static void Init(string clientKey = "", string clientSecret = "", string clientAid = "")
        {
            ClientKey = clientKey;
            ClientAid = clientAid;
            ClientSecret = clientSecret.UrlSafe64Decode();
        }
        private static string sessionID(int amount)
        {
            Random rnd = new Random();
            string chrs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chrs, amount).Select(s => s[rnd.Next(s.Length)]).ToArray());
        }
        
        /// <summary>
        /// Authencate (or login), Authencates user with username, password and HWID
        /// </summary>
        /// <param name="username">User Registered Username</param>
        /// <param name="password">User Registered Password</param>
        /// <param name="hwid">The Unique Hardware Identification ID from the user Device</param>
        /// <example>
        /// ChanChanAuth.Authencate(username: "Raphiel", password: "Raphiel1124", hwid: "HWID-GOES-HERE");
        /// </example>
        public static string Authencate(string username = "", string password = "", string hwid = "")
        {
            if (string.IsNullOrEmpty(username) || username.Length < 3)
                throw new InvaldLength("username Length must be more than 2!");
            else if (string.IsNullOrEmpty(password) || password.Length < 3)
                throw new InvaldLength("password Length must be more than 2!");
            else if (string.IsNullOrEmpty(hwid) || hwid.Length < 3)
                throw new InvaldLength("username Length must be more than 2!");
            else
            {
                if (ClientAid != "" || ClientKey != "")
                {
                    using (HttpRequest cl = new HttpRequest()
                    {
                        KeepAlive = true,
                        IgnoreProtocolErrors = true
                    })
                    {
                        string SessionID = sessionID(40);
                        var PayLoad = "{\"username\": \"" + username + "\",\"password\": \"" + password + "\",\"hwid\": \"" + hwid + "\",\"sessionID\": \"" + SessionID + "\"}";
                        try
                        {
                            string encrypedPayload = SimpleFernet.Encrypt(ClientSecret, PayLoad.Replace("\\\"", "\"").ToBase64String().UrlSafe64Decode());
                            cl.AddHeader("data", encrypedPayload);
                            cl.AddHeader("aid", ClientAid);
                            var prms = new RequestParams();
                            prms["key"] = ClientKey;
                            string resp = cl.Get("https://api.ccauth.app/api/v3/authenticate", prms).ToString();
                            var data = JObject.Parse(SimpleFernet.Decrypt(ClientSecret, resp, out var timestamp).UrlSafe64Encode().FromBase64String());
                            if ((string)data["error"] == "True")
                                throw new UnknownError("Unknown Error, Please Report to the developer.");
                            else
                            {
                                if ((string)data["is_Authenticated"] == "True" && (string)data["session_ID"] == SessionID)
                                    return "Authencated";
                                else if ((string)data["invalid_hwid"] == "True")
                                    return "Invalid HWID";
                                else if ((string)data["expired_license"] == "True")
                                    return "Expired";
                                else if ((string)data["invalid_credentials"] == "True")
                                    return "Invalid Creds";
                                else
                                    return "Unknown Response.\nResp : " + resp.ToString();
                            }
                        }
                        catch (Exception err)
                        {
                            if (err.ToString().Contains("not a valid Base-64"))
                                throw new InvalidSecret("Client Secret is not Base64! Please ReCheck");
                            return "Error: " + err.ToString();
                        }
                    }
                }
                else
                {
                    throw new EmptyRequiredInfo("Some Required Keys Are Required!, Please Re-Initiate");
                }
            }
        }

        /// <summary>
        /// Authencate (or login), Authencates user with username, password and HWID
        /// </summary>
        /// <param name="username">User Registered Username</param>
        /// <param name="password">User Registered Password</param>
        /// <param name="hwid">The Unique Hardware Identification ID from the user Device</param>
        /// <example>
        /// ChanChanAuth.Authencate(username: "Raphiel", password: "Raphiel1124", hwid: "HWID-GOES-HERE");
        /// </example>
        public static string Register(string discord = "", string username = "", string RegKey = "", string password = "", string hwid = "")
        {
            if (string.IsNullOrEmpty(username) || username.Length < 3)
                throw new InvaldLength("username Length must be more than 2!");
            else if (string.IsNullOrEmpty(RegKey) || RegKey.Length < 3)
                throw new InvaldLength("RegKey Length must be more than 2!");
            else if (string.IsNullOrEmpty(password) || password.Length < 3)
                throw new InvaldLength("password Length must be more than 2!");
            else if (string.IsNullOrEmpty(hwid) || hwid.Length < 3)
                throw new InvaldLength("username Length must be more than 2!");
            else
            {
                if (ClientAid != "" || ClientKey != "")
                {
                    using (HttpRequest cl = new HttpRequest()
                    {
                        KeepAlive = true,
                        IgnoreProtocolErrors = true
                    })
                    {
                        string SessionID = sessionID(40);
                        var PayLoad = "{\"username\": \"" + username + "\",\"password\": \"" + password + "\",\"hwid\": \"" + hwid + "\",\"sessionID\": \"" + SessionID + "\"}";
                        try
                        {
                            cl.AddHeader("user", username);
                            cl.AddHeader("pass", password);
                            cl.AddHeader("regkey", RegKey);
                            cl.AddHeader("discord", discord);
                            cl.AddHeader("aid", ClientAid);
                            cl.AddHeader("hwid", hwid);

                            var prms = new RequestParams();
                            prms["key"] = ClientKey;
                            string resp = cl.Get("https://api.ccauth.app/api/v2/register", prms).ToString();
                            var data = JObject.Parse(resp);
                            if ((string)data["error"] == "True")
                                throw new UnknownError("Unknown Error, Please Report to the developer.");
                            else
                            {
                                if ((string)data["success"] == "True")
                                    return "Registered Successfully";
                                else if ((string)data["registration_enabled"] == "False")
                                    return "Registeration isint enabled.";
                                else if ((string)data["invalid_key"] == "True")
                                    return "Invalid Key";
                                else
                                    return "Unknown Response";
                            }
                        }
                        catch (Exception err)
                        {
                            return "Error " + err.ToString();
                        }
                    }
                }
                else
                {
                    throw new EmptyRequiredInfo("Some Required Keys Are Required!, Please Re-Initiate");
                }
            }
        }
        /// <summary>
        /// Reset HWID For a user
        /// </summary>
        /// <param name="username">User Registered Username</param>
        /// <param name="password">User Registered Password</param>
        /// <param name="hwid">The New Unique Hardware Identification ID from the user Device</param>
        /// <param name="key">The Reset Key</param>
        /// <example>
        /// ChanChanAuth.ResetHWID(username: "Raphiel", password: "Raphiel1124", hwid: "HWID-GOES-HERE", key: "HWID Reset Key");
        /// </example>
        public static string ResetHWID(string username, string password, string hwid, string key)
        {
            if (string.IsNullOrEmpty(username) || username.Length < 3)
                throw new InvaldLength("username Length must be more than 2!");
            else if (string.IsNullOrEmpty(key) || key.Length < 3)
                throw new InvaldLength("Key Length must be more than 2!");
            else if (string.IsNullOrEmpty(password) || password.Length < 3)
                throw new InvaldLength("password Length must be more than 2!");
            else if (string.IsNullOrEmpty(hwid) || hwid.Length < 3)
                throw new InvaldLength("username Length must be more than 2!");
            else
            {
                if (ClientAid != "" || ClientKey != "")
                {
                    using (HttpRequest cl = new HttpRequest()
                    {
                        KeepAlive = true,
                        IgnoreProtocolErrors = true
                    })
                    {
                        string SessionID = sessionID(40);
                        var PayLoad = "{\"username\": \"" + username + "\",\"password\": \"" + password + "\",\"hwid\": \"" + hwid + "\",\"sessionID\": \"" + SessionID + "\"}";
                        try
                        {
                            cl.AddHeader("user", username);
                            cl.AddHeader("pass", password);
                            cl.AddHeader("newhwid", hwid);
                            cl.AddHeader("hwidresetkey", key);
                            cl.AddHeader("aid", ClientAid);

                            var prms = new RequestParams();
                            prms["key"] = ClientKey;
                            string resp = cl.Get("https://api.ccauth.app/api/v3/reset", prms).ToString();
                            var data = JObject.Parse(resp);
                            if ((string)data["error"] == "True")
                                throw new UnknownError("Unknown Error, Please Report to the developer.");
                            else
                            {
                                if ((string)data["success"] == "True")
                                    return "Reset Successfully";
                                else if ((string)data["hwid_resets"] == "False")
                                    return "Restes isint enabled.";
                                else if ((string)data["invalid_key"] == "True")
                                    return "Invalid Key";
                                else if ((string)data["reset_today"] == "True")
                                    return "User has Reseted today";
                                else
                                    return "Unknown Response";
                            }
                        }
                        catch (Exception err)
                        {
                            return "Error " + err.ToString();
                        }
                    }
                }
                else
                {
                    throw new EmptyRequiredInfo("Some Required Keys Are Required!, Please Re-Initiate");
                }
            }
        }
    }
}