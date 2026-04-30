using System;
using System.Data;
using MySql.Data.MySqlClient;

//Project -> Manage NuGet Packages -> Browse -> MySql.Data (à télécharger)


Console.WriteLine("Hello, World!");

string server = "localhost";
string uid = "root";
string password = "";
string database = "bibliofusion3";

string conString = $"server={server};uid={uid};pwd={password};database={database}";

try
{
    using var con = new MySqlConnection(conString);
    con.Open();

    using var cmd = new MySqlCommand("SHOW TABLES", con);
    using var reader = cmd.ExecuteReader();

    int count = 0;
    while (reader.Read())
    {
        Console.WriteLine(reader.GetString(0));
        count++;
    }

    Console.WriteLine($"Tables found: {count}");
}
catch (Exception ex)
{
    Console.WriteLine("Error: " + ex.Message);
}
