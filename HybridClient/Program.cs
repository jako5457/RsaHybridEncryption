using Common;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

TcpClient client = new TcpClient();

Console.WriteLine("Connecting to server");
client.Connect(IPAddress.Parse("127.0.0.1"),9090);

if (client.Connected)
{
    NetworkStream stream = client.GetStream();

	do
	{
		if (client.Available > 3)
		{
			byte[] buffer = new byte[client.Available];
			stream.Read(buffer,0, buffer.Length);

			RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            Console.WriteLine($"Recieved public key: {Convert.ToBase64String(buffer)}");

			int bytesread;
            rsa.ImportRSAPublicKey(new ReadOnlySpan<byte>(buffer),out bytesread);

            Console.WriteLine("Generating AES keys...");
			AesPacket packet = new AesPacket();
            packet.Key = GenerateRandomNumber(32);
			packet.iv = GenerateRandomNumber(16);

			string packetmessage = JsonSerializer.Serialize(packet);
			byte[] data = rsa.Encrypt(System.Text.Encoding.UTF8.GetBytes(packetmessage),false);
			stream.Write(data,0,data.Length);

			// create aes object
			using Aes aes = Aes.Create();
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.PKCS7;
			aes.Key = packet.Key;
			aes.IV = packet.iv;

			var encryptor = aes.CreateEncryptor();

            do
			{
                Console.Write("> ");
                string msg = Console.ReadLine();
				byte[] datatosend = aes.EncryptCbc(System.Text.Encoding.UTF8.GetBytes(msg), packet.iv);

				stream.Write(datatosend);

            } while (client.Connected);

            Console.ReadLine();

        }
	} while (client.Available < 3);
	
}

byte[] GenerateRandomNumber(int length)
{
    using RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();
    byte[] randomNumber = new byte[length];
    randomNumberGenerator.GetBytes(randomNumber);

    return randomNumber;
}