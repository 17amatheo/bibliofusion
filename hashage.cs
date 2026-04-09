using Konscious.Security.Cryptography;
using System.Text;

string HashPasswordToB64(string password)
{
    try
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Le mot de passe est vide.");

        byte[] salt = new byte[16];

        using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
        {
            rng.GetBytes(salt);
        }

        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 1,
            Iterations = 3,
            MemorySize = 65536,
        };

        byte[] hashBytes = argon2.GetBytes(64);

        byte[] combined = new byte[salt.Length + hashBytes.Length];
        Array.Copy(salt, 0, combined, 0, salt.Length);
        Array.Copy(hashBytes, 0, combined, salt.Length, hashBytes.Length);

        return Convert.ToBase64String(combined);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erreur lors du hash du mot de passe : {ex.Message}");
        return null; // ou throw; si tu veux propager l'erreur
    }
}

bool isHashValid(string password, string storedHash)
{
    try
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Mot de passe invalide.");

        if (string.IsNullOrWhiteSpace(storedHash))
            throw new ArgumentException("Hash stocké invalide.");

        byte[] hashBytes = Convert.FromBase64String(storedHash);

        if (hashBytes.Length < 80) // 16 sel + 64 hash
            throw new FormatException("Le hash stocké est invalide ou corrompu.");

        byte[] salt = new byte[16];
        Array.Copy(hashBytes, 0, salt, 0, 16);

        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 1,
            Iterations = 3,
            MemorySize = 65536,
        };

        byte[] computedHash = argon2.GetBytes(64);

        byte[] storedHashOnly = new byte[64];
        Array.Copy(hashBytes, 16, storedHashOnly, 0, 64);

        return computedHash.SequenceEqual(storedHashOnly);
    }
    catch (FormatException)
    {
        Console.WriteLine("Le hash n'est pas en Base64 valide.");
        return false;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erreur lors de la vérification : {ex.Message}");
        return false;
    }
}


// Exemples
try
{
    var hash1 = HashPasswordToB64("HelloThisIsAVeryStrongp@ssw0rd");
    var hash2 = HashPasswordToB64("HelloThisIsAVeryStrongp@ssw0rd");

    Console.WriteLine(hash1);
    Console.WriteLine(hash2);

    bool isValid = isHashValid(
        "HelloThisIsAVeryStrongp@ssw0rd",
        "8KaLNsdeGBGuH4nldrZyR6xekYDhWwqMgF3uIYVYQvD38Q2OsDRW8d+uhyDvFUsQSzimKd8zwEkhy3c8JSilgrrL8syM/R7d+5A+dpR0WN4="
    );

    Console.WriteLine(isValid);
}
catch (Exception ex)
{
    Console.WriteLine($"Erreur globale : {ex.Message}");
}
