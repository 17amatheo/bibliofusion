using System;
using System.Collections.Generic;
using MySql.Data.MySqlClient;
using System.Security.Cryptography;
using System.Text;
string cle = "clee_SuP3r_S3cr3t3";


string conString = "server=localhost;uid=root;pwd=;database=bibliofusion3";


/////////////////////////////////////////////////////
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





///////////////////////////////////////

















bool inserer = false; // true pour insérer, false pour lire et déchiffrer



try
{
    if (inserer)
    {
        Console.WriteLine("Insertion de données chiffrées...");
        using var con = new MySqlConnection(conString);
        con.Open();

        // Valeurs à insérer (exemple)
        string nom = "Test";
        string prenom = "Chiffrement";
        DateTime dateNaissance = new DateTime(2000, 1, 1);
        string adresse = "123 Rue de la Sécurité";
        string codePostal = "75000";
        string email = "testch@mail.com";
        string numMobile = "0678889122";
        string numFixe = "0323574822";

        // Chiffrement (fonctions existantes : Chiffrer / Dechiffrer)
        string prenomchiffre = Chiffrer(prenom, cle);           //pas ch
        string nomchiffre = Chiffrer(nom, cle);                 //pas ch
        string adressechiffre = Chiffrer(adresse, cle);          //chif
        string emailchiffre = Chiffrer(email, cle);             //chif
        string nummobilechiffre = Chiffrer(numMobile, cle);        //chif
        string numfixechiffre = Chiffrer(numFixe, cle);         //chif 
        Console.WriteLine("prenomchiffre: "+prenomchiffre+"\n");
        // INSERT
        using (var insertCmd = new MySqlCommand(
            @"INSERT INTO Adherents
              (Nom, Prenom, Date_Naissance, Adresse, Code_Postal, Email, Num_Mobile, Num_Fixe)
              VALUES
              (@Nom, @Prenom, @DateNaissance, @Adresse, @CodePostal, @Email, @NumMobile, @NumFixe);",
            con))
        {
            insertCmd.Parameters.AddWithValue("@Nom", nom);
            insertCmd.Parameters.AddWithValue("@Prenom", prenom);
            insertCmd.Parameters.AddWithValue("@DateNaissance", dateNaissance);
            insertCmd.Parameters.AddWithValue("@Adresse", adressechiffre);
            insertCmd.Parameters.AddWithValue("@CodePostal", codePostal);
            insertCmd.Parameters.AddWithValue("@Email", emailchiffre);
            insertCmd.Parameters.AddWithValue("@NumMobile", nummobilechiffre);
            insertCmd.Parameters.AddWithValue("@NumFixe", numfixechiffre);

            insertCmd.ExecuteNonQuery();
        }
    }
    else
    {
        Console.WriteLine("Lecture et déchiffrement des données...");

        using var con = new MySqlConnection(conString);
        con.Open();

        // Lire uniquement le champ Email (chiffré) et le déchiffrer avant affichage
        using (var selectCmd = new MySqlCommand(
            "SELECT Email FROM Adherents WHERE idAdherents=0;",
            con))
        using (var reader = selectCmd.ExecuteReader())
        {
            var mails = new List<string>();

            while (reader.Read())
            {
                if (reader.IsDBNull(0)) { mails.Add("NULL"); continue; }
                string mailChiffreLu = reader.GetString(0);
                Console.WriteLine("chiffre LU: " + mailChiffreLe + "\n");
                string mailDeChiffre = Dechiffrer(mailChiffreLe, cle);
                Console.WriteLine("DEchiffre LU: " + mailDeChiffre + "\n");
                mails.Add(mailDeChiffre);
            }

            
        }
    }
}
catch (MySqlException mex)
{
    Console.Error.WriteLine($"Erreur MySQL : {mex.Message}");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Erreur : {ex.Message}");
}

