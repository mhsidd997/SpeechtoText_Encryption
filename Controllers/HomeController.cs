using Microsoft.AspNetCore.Mvc;
using SpeechtoText_Encryption.Models;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace SpeechtoText_Encryption.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _config;

        public HomeController(ILogger<HomeController> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
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
                    string speech = speechElement.GetString();

                    string key = _config.GetValue<string>("AESKey");
                    byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                    byte[] speechBytes = Encoding.UTF8.GetBytes(speech);

                    using (Aes aesAlg = Aes.Create())
                    {
                        aesAlg.Key = keyBytes;
                        aesAlg.Mode = CipherMode.ECB;
                        aesAlg.Padding = PaddingMode.PKCS7;

                        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                        
                        using (MemoryStream msEncrypt = new MemoryStream())
                        {
                            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            {
                                csEncrypt.Write(speechBytes, 0, speechBytes.Length);
                            }

                            byte[] encryptedBytes = msEncrypt.ToArray();

                            string cipherText = Convert.ToBase64String(encryptedBytes);

                            return Ok(new { cipherText = cipherText });
                        }
                    }
                }
                else
                {
                    return BadRequest("Speech data is missing in the request.");
                }
            }
            catch (Exception ex)
            {
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
                    string cipherText = cipherTextElement.GetString();

                    string key = _config.GetValue<string>("AESKey");
                    byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                    byte[] cipherBytes = Convert.FromBase64String(cipherText);

                    using (Aes aesAlg = Aes.Create())
                    {
                        aesAlg.Key = keyBytes;
                        aesAlg.Mode = CipherMode.ECB;
                        aesAlg.Padding = PaddingMode.PKCS7;

                        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                        
                        using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
                        {
                            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {
                                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                {
                                    string decryptedText = srDecrypt.ReadToEnd();

                                    return Ok(new { decryptedText = decryptedText });
                                }
                            }
                        }
                    }
                }
                else
                {
                    return BadRequest("Cipher text is missing in the request.");
                }
            }
            catch (Exception ex)
            {
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
