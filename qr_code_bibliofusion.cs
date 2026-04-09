using System;
using System.Text;
using System.Security.Cryptography;

//Clee secrete (a stocker dans un fichier de config) PAS ICI
string secretKey = "CLEE_VR@1M3NT_SECRETE";

string Sign(string data, string secretKey)
{
    //signe un payload 
    var keyBytes = Encoding.UTF8.GetBytes(secretKey);
    var dataBytes = Encoding.UTF8.GetBytes(data);

    using (var hmac = new HMACSHA256(keyBytes))
    {
        var hash = hmac.ComputeHash(dataBytes);
        return Convert.ToBase64String(hash);

    }



}

string CreateCard(string cardid, string version, string secretKey)
{  
    //crée un payload de carte
    string payload = cardid + ";" + version;
    string signature = Sign(payload, secretKey);
    return payload + ";" + signature;
}

bool VerifyCard(string card, string secretKey)
  //verifie la carte (valide / pas valide)
{
    var parts = card.Split(';');
    if (parts.Length != 3) 
    {
        return false;
            
    }
    string payload = parts[0] + ";" + parts[1];
    string signature = parts[2];
    string exceptedSignature = Sign(payload, secretKey);

    try
    {
        return CryptographicOperations.FixedTimeEquals(
        Convert.FromBase64String(signature),
        Convert.FromBase64String(exceptedSignature)
        );

    }
    catch (Exception ex) 
        {
            //erreur de format / mauvaise carte
            return false;
        }
}

string card = CreateCard("12345", "1", secretKey);
Console.WriteLine("Carte : " + card);

bool isValid = VerifyCard("12345;1;WGh5hB97yjjQcF6E9OC1GV5oyAJbAJ2PbuqfWUC/fFQ=", secretKey);
Console.WriteLine("Valid? : " + isValid);
