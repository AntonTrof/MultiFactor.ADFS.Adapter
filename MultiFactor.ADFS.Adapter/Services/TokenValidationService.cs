using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Security;

namespace MultiFactor.ADFS.Adapter.Services
{
    /// <summary>
    /// Service to load public key and verify token signature, issuer and expiration date
    /// </summary>
    public class TokenValidationService
    {
        private readonly MultiFactorConfiguration _configuration;
        private const int MAX_TOKEN_LIFETIME_MINUTES = 5;
        private static readonly ConcurrentDictionary<string, DateTime> _usedNonces = new();

        public class TokenPayload
        {
            public string Aud { get; set; }
            public long Exp { get; set; }
            public string Sub { get; set; }
            public string Domain { get; set; }
            public string SessionId { get; set; }
            public string ContextTokenHash { get; set; }
            public string Nonce { get; set; }
        }

        public TokenValidationService(MultiFactorConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        /// <summary>
        /// Generate JWT when Bypass mode. 
        /// </summary>
        public string GenerateBypassToken(string login, string domain, string sessionId, string contextToken)
        {
            var key = Encoding.UTF8.GetBytes(_configuration.ApiSecret);
            var origtime = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            var exptime = DateTime.UtcNow.AddMinutes(MAX_TOKEN_LIFETIME_MINUTES);

            var payload = new TokenPayload
            {
                Aud = _configuration.ApiKey,
                Exp = (long)(exptime - origtime).TotalSeconds,
                Sub = login,
                Domain = domain,
                SessionId = sessionId,
                ContextTokenHash = ComputeHash(contextToken),
                Nonce = GenerateNonce()
            };

            var body = Util.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
            var head = Util.Base64UrlEncode(Encoding.UTF8.GetBytes("{\"typ\":\"JWT\",\"alg\":\"HS256\"}"));
            var message = $"{head}.{body}";
            var sign = Util.Base64UrlEncode(Util.HMACSHA256(key, Encoding.UTF8.GetBytes(message)));

            return $"bypass.{message}.{sign}";
        }

        /// <summary>
        /// Verify JWT
        /// </summary>
        public string VerifyToken(string jwt, string expectedDomain = null, string contextToken = null)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                throw new ArgumentNullException(nameof(jwt));
            }

            try
            {
                var parts = jwt.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
                var bypass = false;
                if (parts[0] == "bypass") bypass = true;

                if (parts.Length < (bypass ? 4 : 3))
                {
                    throw new SecurityException("Invalid token format");
                }

                var head = parts[bypass ? 1 : 0];
                var body = parts[bypass ? 2 : 1];
                var sign = parts[bypass ? 3 : 2];

                // Validate signature
                ValidateSignature(head, body, sign);

                // Decode and validate payload
                var decodedBody = Encoding.UTF8.GetString(Util.Base64UrlDecode(body));
                var payload = JsonSerializer.Deserialize<TokenPayload>(decodedBody);

                // Validate token fields
                ValidateTokenFields(payload, expectedDomain, contextToken);

                return payload.Sub;
            }
            catch (Exception ex)
            {
                Logger.Error($"Token validation failed

ChatGPT 4 | Claude | Jadve AI, [27.11.2024 17:56]
: {ex.Message}");
                throw new SecurityException("Token validation failed", ex);
            }
        }

        private void ValidateSignature(string head, string body, string sign)
        {
            var key = Encoding.UTF8.GetBytes(configuration.ApiSecret);
            var message = Encoding.UTF8.GetBytes($"{head}.{body}");
            var computedSign = Util.Base64UrlEncode(Util.HMACSHA256(key, message));

            if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(computedSign),
                Convert.FromBase64String(sign)))
            {
                throw new SecurityException("Invalid token signature");
            }
        }

        private void ValidateTokenFields(TokenPayload payload, string expectedDomain, string contextToken)
        {
            // Validate audience
            if (payload.Aud != configuration.ApiKey)
            {
                throw new SecurityException("Invalid token audience");
            }

            // Validate expiration
            var tokenExpiration = Util.UnixTimeStampToDateTime(payload.Exp);
            if (tokenExpiration < DateTime.UtcNow)
            {
                throw new SecurityException("Token has expired");
            }

            if (DateTime.UtcNow.AddMinutes(MAXTOKENLIFETIMEMINUTES) < tokenExpiration)
            {
                throw new SecurityException("Token lifetime exceeds maximum allowed");
            }

            // Validate domain if provided
            if (!string.IsNullOrEmpty(expectedDomain) && payload.Domain != expectedDomain)
            {
                throw new SecurityException("Invalid token domain");
            }

            // Validate context token if provided
            if (!string.IsNullOrEmpty(contextToken) && 
                payload.ContextTokenHash != ComputeHash(contextToken))
            {
                throw new SecurityException("Invalid context token binding");
            }

            // Validate and invalidate nonce
            ValidateNonce(payload.Nonce);

            // Validate required fields
            if (string.IsNullOrEmpty(payload.Sub) ||
                string.IsNullOrEmpty(payload.SessionId) ||
                string.IsNullOrEmpty(payload.Nonce))
            {
                throw new SecurityException("Missing required token fields");
            }
        }

        private void ValidateNonce(string nonce)
        {
            if (string.IsNullOrEmpty(nonce))
            {
                throw new SecurityException("Missing nonce");
            }

            if (!usedNonces.TryAdd(nonce, DateTime.UtcNow))
            {
                throw new SecurityException("Nonce has already been used");
            }

            CleanupExpiredNonces();
        }

        private void CleanupExpiredNonces()
        {
            var expirationTime = DateTime.UtcNow.AddMinutes(-MAXTOKENLIFETIMEMINUTES);
            foreach (var nonce in usedNonces)
            {
                if (nonce.Value < expirationTime)
                {
                    usedNonces.TryRemove(nonce.Key, out );
                }
            }
        }

        private string GenerateNonce()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        }

        private string ComputeHash(string input)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(input);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Verify JWT safe
        /// </summary>
        public bool TryVerifyToken(string jwt, out string identity)
        {
            try
            {
                identity = VerifyToken(jwt);
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to parse token: {ex.Message}, {ex}");
                identity = null;
                return false;
            }
        }

        /// <summary>
        /// Verify JWT safe with domain and context token validation
        /// </summary>
        public bool TryVerifyToken(string jwt, string expectedDomain, string contextToken, out string identity)
        {
            try
            {
                identity = VerifyToken(jwt, expectedDomain, contextToken);
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to parse token: {ex.Message}, {ex}");
                identity = null;
                return false;
            }
        }
    }
}
