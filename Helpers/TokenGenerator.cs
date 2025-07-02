using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace ProgrammaticExportSampleAppMPN.Helpers
{
	public class TokenGenerator
	{
		private readonly ILogger<TokenGenerator> _logger;
		private readonly IConfiguration _configuration;
		public const int TokenGenerateRetryCount = 3;
		public string AccessToken { get; set; }
		public string RefreshToken { get; set; }
		public long ExpiryTime;

		public TokenGenerator(ILogger<TokenGenerator> logger, IConfiguration configuration)
		{
			_logger = logger;
			_configuration = configuration;
		}

		private async Task<HttpResponseMessage> PostFormUrlEncoded(string url, Dictionary<string, string> postData)
		{
			var client = new HttpClient();
			var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(postData) };
			return await client.SendAsync(req);
		}

		public async Task<string> GenerateADTokenWithRetries()
		{
			string accessToken = string.Empty;
			for (int i = 0; i < TokenGenerateRetryCount; i++)
			{
				try
				{
					//accessToken = await GenerateAdToken();
					accessToken = await GenerateClientCredentialsTokenAsync();
					break;
				}
				catch (Exception e)
				{
					_logger.LogError($"Token generation attempt {i} failed: {e.Message}");
					continue;
				}
			}

			return accessToken;
		}

		public async Task<string> GenerateAdToken()
		{
			long currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
			Dictionary<string, string> postData = new Dictionary<string, string>();

			var finalTokenUrl = String.Format(
				_configuration["AdTokenConfig:TokenGenerateUrl"],
				_configuration["AdTokenConfig:TenantId"]);

			// All the ID, secret and other passwords should be fetched from KeyVault. It is in the config file
			// Only for demo purposes.

			// Validate required configuration values
			var clientId = _configuration["AdTokenConfig:WebAppClientId"];
			var clientSecret = _configuration["AdTokenConfig:WebAppClientSecret"];
			var username = _configuration["AdTokenConfig:Username"];
			var password = _configuration["AdTokenConfig:Password"];
			var resourceId = _configuration["AdTokenConfig:ResourceId"];

			if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) ||
				string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
			{
				throw new InvalidOperationException("Missing required Azure AD configuration values. Please check AdTokenConfig settings.");
			}

			postData.Add("resource", resourceId);
			postData.Add("client_id", clientId);
			postData.Add("client_secret", clientSecret);
			postData.Add("username", username);
			postData.Add("password", password);
			postData.Add("scope", "openid");

			// On first run or when access token or refresh token are empty, generate from scratch
			if (ExpiryTime == 0 || string.IsNullOrEmpty(AccessToken) || string.IsNullOrEmpty(RefreshToken))
			{
				postData.Add("grant_type", "password");
			}
			else if (currentTime > (ExpiryTime - 300))
			{
				// Regenerate token if we are 5 min away from expiry
				postData.Add("grant_type", "refresh_token");
				postData.Add("refresh_token", RefreshToken);
			}
			else
			{
				// Token is still valid, return existing token
				return AccessToken;
			}

			TokenGeneratorResponseObject tokenGeneratorResponseObject;
			try
			{
				HttpResponseMessage response = await PostFormUrlEncoded(finalTokenUrl, postData);
				if ((int)response.StatusCode != 200)
				{
					_logger.LogError("Token generation failed with status code: {StatusCode}", response.StatusCode);
					throw new Exception($"Token generation failed with status code: {response.StatusCode}");
				}

				var content = await response.Content.ReadAsStringAsync();
				tokenGeneratorResponseObject = JsonConvert.DeserializeObject<TokenGeneratorResponseObject>(content);

				if (string.IsNullOrEmpty(tokenGeneratorResponseObject.access_token))
				{
					_logger.LogError("Token generation returned no access token");
					throw new Exception("Token generation returned no access token");
				}
			}
			catch (Exception e)
			{
				_logger.LogError($"Exception in token generation: {e.Message}");
				// Set expiry time to 0 on errors, so that on the next retry we generate token from scratch
				ExpiryTime = 0;
				throw new Exception($"Exception in token generation: {e.Message}");
			}

			// Update stored token information
			AccessToken = tokenGeneratorResponseObject.access_token;
			RefreshToken = tokenGeneratorResponseObject.refresh_token;
			ExpiryTime = long.Parse(tokenGeneratorResponseObject.expires_on);

			return AccessToken;
		}

		// Alternative implementation using Client Credentials flow
		public async Task<string> GenerateClientCredentialsTokenAsync()
		{

			long currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
			//Dictionary<string, string> postData = new Dictionary<string, string>();

			var finalTokenUrl = String.Format(
				_configuration["AdTokenConfig:TokenGenerateUrl"],
				_configuration["AdTokenConfig:TenantId"]);

			// All the ID, secret and other passwords should be fetched from KeyVault. It is in the config file
			// Only for demo purposes.

			// Validate required configuration values
			var clientId = _configuration["AdTokenConfig:WebAppClientId"];
			var clientSecret = _configuration["AdTokenConfig:WebAppClientSecret"];
			var username = _configuration["AdTokenConfig:Username"];
			var password = _configuration["AdTokenConfig:Password"];
			var resourceId = _configuration["AdTokenConfig:ResourceId"];

			if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
			{
				throw new InvalidOperationException("Missing required Azure AD configuration values. Please check AdTokenConfig settings.");
			}

			// orig
			//postData.Add("resource", resourceId);
			//postData.Add("client_id", clientId);
			//postData.Add("client_secret", clientSecret);
			//postData.Add("username", username);
			//postData.Add("password", password);
			//postData.Add("scope", "openid");

			var postData = new Dictionary<string, string>
			{
				{"client_id", clientId},
				{"client_secret", clientSecret},
				{"scope", "https://api.partnercenter.microsoft.com/.default"}
				//{"grant_type", "client_credentials"}
			};

			// On first run or when access token or refresh token are empty, generate from scratch
			if (ExpiryTime == 0 || string.IsNullOrEmpty(AccessToken) || string.IsNullOrEmpty(RefreshToken))
			{
				//postData.Add("grant_type", "password");
				postData.Add("grant_type", "client_credentials");

			}
			else if (currentTime > (ExpiryTime - 300))
			{
				// Regenerate token if we are 5 min away from expiry
				postData.Add("grant_type", "refresh_token");
				postData.Add("refresh_token", RefreshToken);
			}
			else
			{
				// Token is still valid, return existing token
				return AccessToken;
			}

			TokenGeneratorResponseObject tokenGeneratorResponseObject;
			try
			{
				HttpResponseMessage response = await PostFormUrlEncoded(finalTokenUrl, postData);
				if ((int)response.StatusCode != 200)
				{
					_logger.LogError("Token generation failed with status code: {StatusCode}", response.StatusCode);
					throw new Exception($"Token generation failed with status code: {response.StatusCode}");
				}

				var content = await response.Content.ReadAsStringAsync();
				tokenGeneratorResponseObject = JsonConvert.DeserializeObject<TokenGeneratorResponseObject>(content);

				if (string.IsNullOrEmpty(tokenGeneratorResponseObject.access_token))
				{
					_logger.LogError("Token generation returned no access token");
					throw new Exception("Token generation returned no access token");
				}
			}
			catch (Exception e)
			{
				_logger.LogError($"Exception in token generation: {e.Message}");
				// Set expiry time to 0 on errors, so that on the next retry we generate token from scratch
				ExpiryTime = 0;
				throw new Exception($"Exception in token generation: {e.Message}");
			}

			// Update stored token information
			AccessToken = tokenGeneratorResponseObject.access_token;
		 

			return AccessToken;

			 
		}
	}
}