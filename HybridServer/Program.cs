using System.Web;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Net;
using System.Text;
using Common;
using System.Text.Json;
using System.Net.Http.Headers;

RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);

var Publickey = rsa.ExportRSAPublicKey();
Console.WriteLine($"Public key created: \n{Convert.ToBase64String(Publickey)}");

// Start server
TcpListener Server = new TcpListener(IPAddress.Parse("127.0.0.1"), 9090);
Server.Start();

Console.WriteLine("Listening to clients...");
TcpClient client = Server.AcceptTcpClient();

NetworkStream stream = client.GetStream();

Console.WriteLine("Sending Public key to client");
stream.Write(Publickey);

Console.WriteLine("Waiting for response");
while (client.Available < 3) { }

byte[] buffer = new byte[client.Available];

stream.Read(buffer, 0, buffer.Length);


buffer = rsa.Decrypt(buffer,false);
string packetInfo = Encoding.UTF8.GetString(buffer);

Console.WriteLine("Recieved packetInfo");
Console.WriteLine(packetInfo);

AesPacket packet = JsonSerializer.Deserialize<AesPacket>(packetInfo);

using Aes aes = Aes.Create();

aes.Mode = CipherMode.CBC;
aes.Padding = PaddingMode.PKCS7;
aes.Key = packet.Key;
aes.IV = packet.iv;

do
{
	if (stream.DataAvailable)
	{
		byte[] databuffer = new byte[client.Available];
		stream.Read(databuffer, 0, databuffer.Length);

		databuffer = aes.DecryptCbc(databuffer, packet.iv);

		Console.WriteLine(System.Text.Encoding.UTF8.GetString(databuffer));
	}
} while (client.Connected);



Console.WriteLine("Recieved keydata: ");




