using System;
using System.Security.Cryptography;
using System.Text;
string cle = "clee_SuP3r_S3cr3t3";   //Clé secrète (à stocker ailleurs dans un fichier config)


static string Chiffrer(string donnees, string cle)
{
    try
    {
        if (string.IsNullOrWhiteSpace(donnees))
            throw new ArgumentException("Les données à chiffrer ne peuvent pas être vides.");

        if (string.IsNullOrWhiteSpace(cle))
            throw new ArgumentException("La clé ne peut pas être vide.");

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = Encoding.UTF8.GetBytes(donnees);

        // Dérivation de clé (PBKDF2)
        using var kdf = new Rfc2898DeriveBytes(cle, salt, 100000, HashAlgorithmName.SHA256);
        byte[] key = kdf.GetBytes(32);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        // Format final : salt + nonce + tag + ciphertext
        byte[] result = new byte[salt.Length + nonce.Length + tag.Length + ciphertext.Length];

        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
        Buffer.BlockCopy(nonce, 0, result, salt.Length, nonce.Length);
        Buffer.BlockCopy(tag, 0, result, salt.Length + nonce.Length, tag.Length);
        Buffer.BlockCopy(ciphertext, 0, result, salt.Length + nonce.Length + tag.Length, ciphertext.Length);

        return Convert.ToBase64String(result);
    }
    catch (CryptographicException ex)
    {
        throw new Exception($"Erreur cryptographique lors du chiffrement : {ex.Message}");
    }
    catch (Exception ex)
    {
        throw new Exception($"Erreur lors du chiffrement : {ex.Message}");
    }
}

static string Dechiffrer(string donneeChiffree, string cle)
{
    try
    {
        if (string.IsNullOrWhiteSpace(donneeChiffree))
            throw new ArgumentException("Les données chiffrées ne peuvent pas être vides.");

        if (string.IsNullOrWhiteSpace(cle))
            throw new ArgumentException("La clé ne peut pas être vide.");

        byte[] full = Convert.FromBase64String(donneeChiffree);

        if (full.Length < 16 + 12 + 16)
            throw new ArgumentException("Les données chiffrées sont invalides ou corrompues.");

        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[full.Length - (16 + 12 + 16)];

        Buffer.BlockCopy(full, 0, salt, 0, 16);
        Buffer.BlockCopy(full, 16, nonce, 0, 12);
        Buffer.BlockCopy(full, 28, tag, 0, 16);
        Buffer.BlockCopy(full, 44, ciphertext, 0, ciphertext.Length);

        // Dérivation de clé identique
        using var kdf = new Rfc2898DeriveBytes(cle, salt, 100000, HashAlgorithmName.SHA256);
        byte[] key = kdf.GetBytes(32);

        byte[] plaintext = new byte[ciphertext.Length];

        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        return Encoding.UTF8.GetString(plaintext);
    }
    catch (FormatException)
    {
        throw new Exception("Le format Base64 est invalide.");
    }
    catch (CryptographicException)
    {
        throw new Exception("Échec du déchiffrement : clé incorrecte ou données altérées.");
    }
    catch (Exception ex)
    {
        throw new Exception($"Erreur lors du déchiffrement : {ex.Message}");
    }
}


//Exemple d'utilisation
string donnees = "Jean Dupont";
try
   {
        string chiffre = Chiffrer(donnees, cle);
        Console.WriteLine($"Données chiffrées : {chiffre}");

        string dechiffre = Dechiffrer(chiffre, cle);
        Console.WriteLine($"Données déchiffrées : {dechiffre}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erreur : {ex.Message}");
    }


