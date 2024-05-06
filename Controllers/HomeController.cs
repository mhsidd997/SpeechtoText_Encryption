using Microsoft.AspNetCore.Mvc;
using SpeechtoText_Encryption.Models;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SpeechtoText_Encryption.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult EncryptSpeech([FromBody] JsonElement requestBody)
        {
            try
            {
                if (requestBody.TryGetProperty("speech", out JsonElement speechElement))
                {
                    // Get the speech text
                    string speech = speechElement.GetString();

                    // Encrypt the received speech using AES encryption algorithm
                    string key = "1234567890123456"; // Replace with your secret key
                    byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                    byte[] speechBytes = Encoding.UTF8.GetBytes(speech);

                    using (Aes aesAlg = Aes.Create())
                    {
                        aesAlg.Key = keyBytes;
                        aesAlg.Mode = CipherMode.ECB; // Choose appropriate mode
                        aesAlg.Padding = PaddingMode.PKCS7; // Choose appropriate padding mode

                        // Create an encryptor to perform the stream transform
                        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                        // Create the streams used for encryption
                        using (MemoryStream msEncrypt = new MemoryStream())
                        {
                            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            {
                                // Write all data to the stream
                                csEncrypt.Write(speechBytes, 0, speechBytes.Length);
                            }

                            // Get the encrypted bytes from the memory stream
                            byte[] encryptedBytes = msEncrypt.ToArray();

                            // Convert the encrypted bytes to base64 string (for easier transmission)
                            string cipherText = Convert.ToBase64String(encryptedBytes);

                            // Return OK response with the cipher text
                            return Ok(new { cipherText = cipherText });
                        }
                    }
                }
                else
                {
                    // If speech data is missing, return a bad request response
                    return BadRequest("Speech data is missing in the request.");
                }
            }
            catch (Exception ex)
            {
                // If an error occurs during decryption, return a BadRequest response
                _logger.LogError(ex, "An error occurred during decryption.");
                return BadRequest(new { Error = "An error occurred during encryption." });
            }
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult Index2() { 
            return View(); 
        }

        [HttpPost]
        public IActionResult DecryptSpeech([FromBody] JsonElement requestBody)
        {
            try
            {
                if (requestBody.TryGetProperty("cipherText", out JsonElement cipherTextElement))
                {
                    // Get the cipher text
                    string cipherText = cipherTextElement.GetString();

                    // Decrypt the received cipher text using AES decryption algorithm
                    string key = "1234567890123456"; // Replace with your secret key
                    byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                    byte[] cipherBytes = Convert.FromBase64String(cipherText);

                    using (Aes aesAlg = Aes.Create())
                    {
                        aesAlg.Key = keyBytes;
                        aesAlg.Mode = CipherMode.ECB; // Choose appropriate mode
                        aesAlg.Padding = PaddingMode.PKCS7; // Choose appropriate padding mode

                        // Create a decryptor to perform the stream transform
                        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                        // Create the streams used for decryption
                        using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
                        {
                            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {
                                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                {
                                    // Read the decrypted bytes from the decrypting stream
                                    string decryptedText = srDecrypt.ReadToEnd();

                                    // Return OK response with the decrypted text
                                    return Ok(new { decryptedText = decryptedText });
                                }
                            }
                        }
                    }
                }
                else
                {
                    // If cipher text is missing, return a bad request response
                    return BadRequest("Cipher text is missing in the request.");
                }
            }
            catch (Exception ex)
            {
                // If an error occurs during decryption, return a BadRequest response
                _logger.LogError(ex, "An error occurred during decryption.");
                return BadRequest(new { Error = "An error occurred during decryption." });
            }
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
