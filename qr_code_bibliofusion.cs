using System;
using System.Text;
using System.Security.Cryptography;

// Clé secrète (à stocker ailleurs dans un fichier config)
string secretKey = "CLEE_VR@1M3NT_SECRETE";

string Sign(string data, string secretKey)
{
    try
    {
        if (string.IsNullOrWhiteSpace(data))
            throw new ArgumentException("Data invalide.");

        if (string.IsNullOrWhiteSpace(secretKey))
            throw new ArgumentException("Clé secrète invalide.");

        var keyBytes = Encoding.UTF8.GetBytes(secretKey);
        var dataBytes = Encoding.UTF8.GetBytes(data);

        using (var hmac = new HMACSHA256(keyBytes))
        {
            var hash = hmac.ComputeHash(dataBytes);
            return Convert.ToBase64String(hash);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erreur lors de la signature : {ex.Message}");
        return null; // ou throw;
    }
}

string CreateCard(string cardid, string version, string secretKey)
{
    try
    {
        if (string.IsNullOrWhiteSpace(cardid))
            throw new ArgumentException("Card ID invalide.");

        if (string.IsNullOrWhiteSpace(version))
            throw new ArgumentException("Version invalide.");

        string payload = cardid + ";" + version;

        string signature = Sign(payload, secretKey);

        if (signature == null)
            throw new Exception("Échec de la signature.");

        return payload + ";" + signature;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erreur lors de la création de la carte : {ex.Message}");
        return null;
    }
}

bool VerifyCard(string card, string secretKey)
{
    try
    {
        if (string.IsNullOrWhiteSpace(card))
            throw new ArgumentException("Carte invalide.");

        if (string.IsNullOrWhiteSpace(secretKey))
            throw new ArgumentException("Clé secrète invalide.");

        var parts = card.Split(';');

        if (parts.Length != 3)
            return false;

        string payload = parts[0] + ";" + parts[1];
        string signature = parts[2];

        string expectedSignature = Sign(payload, secretKey);

        if (expectedSignature == null)
            return false;

        byte[] sigBytes;
        byte[] expectedBytes;

        try
        {
            sigBytes = Convert.FromBase64String(signature);
            expectedBytes = Convert.FromBase64String(expectedSignature);
        }
        catch (FormatException)
        {
            // Base64 invalide
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(sigBytes, expectedBytes);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erreur lors de la vérification : {ex.Message}");
        return false;
    }
}


// Exemple
try
{
    string card = CreateCard("12345", "1", secretKey);
    Console.WriteLine("Carte : " + card);

    bool isValid = VerifyCard(
        "12345;1;WGh5hB97yjjQcF6E9OC1GV5oyAJbAJ2PbuqfWUC/fFQ=",
        secretKey
    );

    Console.WriteLine("Valid? : " + isValid);
}
catch (Exception ex)
{
    Console.WriteLine($"Erreur globale : {ex.Message}");
}
