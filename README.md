# ChanChanAuth
C# wrapper for https://api.ccauth.app/

-----
Examples
-----
Authencate (Login)
```cs
using System;
using ChanChanAuth;

string username = "Username";
string password = "Password";
string hwid = "HARDWARE-IDENTIFICATION-ID-OR-HWID";
Client.Init("Key", "Secret (Base64)", "AID");
string resp = Client.Authencate(username: username, password: password, hwid: hwid).ToLower();
if (resp.Contains("authencated"))
{
  Console.WriteLine("Authencated");
}
else if (resp.Contains("invalid hwid"))
{
  Console.WriteLine("Invalid HWID");
}
else if (resp.Contains("expired"))
{
  Console.WriteLine("Lisence Expired");
}
else if (resp.Contains("invalid creds"))
{
  Console.WriteLine("Invalid Credintals");
}
else
{
  Console.WriteLine("Unknown Response Returned!");
}
```
-----
Register
-----
```cs
using System;
using ChanChanAuth;

string username = "Username";
string password = "Password";
string Lisence = "Lisence";
string Discord = "DiscordName#6249";
string hwid = "HARDWARE-IDENTIFICATION-ID-OR-HWID";
# 5 In Total

Client.Init("Key", "Secret (Base64)", "AID");
string resp = Client.Register(username: username, password: password, hwid: hwid, RegKey: Lisence, discord: Discord).ToLower();
if (resp.Contains("success"))
{
  Console.WriteLine("Registered Successfully");
}
else if (resp.Contains("registeration isint enabled"))
{
  Console.WriteLine("Registeration isint enabled");
}
else if (resp.Contains("invalid key"))
{
  Console.WriteLine("Invalid Key");
}
else
{
  Console.WriteLine("Unknown Response Returned!");
}
```
-----
TODO: - Add Reset HWID
      - Add Better Filter For Functions
      - Add More Response Code
