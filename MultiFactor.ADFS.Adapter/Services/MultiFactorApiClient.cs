using System;
using System.Net;
using System.Text;

namespace MultiFactor.ADFS.Adapter.Services
{
    public class MultiFactorApiClient
    {
        private readonly MultiFactorConfiguration _configuration;

        public MultiFactorApiClient(MultiFactorConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public string CreateRequest(string login, string target, string postbackUrl)
        {
            var bypass = _configuration.Bypass;
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                // Добавляем domain в payload
                var payload = new
                {
                    Identity = login,
                    Callback = new
                    {
                        Action = postbackUrl,
                        Target = target
                    },
                    Domain = _configuration.Domain // Добавлено
                };

                var json = Util.JsonSerialize(payload);
                var requestData = Encoding.UTF8.GetBytes(json);

                using (var web = new WebClient())
                {
                    web.Headers.Add("Content-Type", "application/json");
                    web.Headers.Add("Authorization", "Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(_configuration.ApiKey + ":" + _configuration.ApiSecret)));

                    if (!string.IsNullOrEmpty(_configuration.ApiProxy))
                    {
                        web.Proxy = new WebProxy(_configuration.ApiProxy);
                    }

                    var responseData = web.UploadData(_configuration.ApiUrl + "/access/requests", "POST", requestData);
                    json = Encoding.UTF8.GetString(responseData);
                    var response = Util.JsonDeserialize<MultiFactorWebResponse<MultiFactorAccessPage>>(json);

                    if (!response.Success)
                    {
                        bypass = false;
                        throw new Exception(response.Message);
                    }
                    return response.Model.Url;
                }
            }
            catch (Exception ex)
            {
                Logger.Error("MultiFactor API error: " + ex.Message);
                if (bypass) return "bypass";
                throw new Exception("MultiFactor API error: " + ex.Message);
            }
        }
    }

    // Оставляем классы без изменений
    public class MultiFactorWebResponse<TModel>
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public TModel Model { get; set; }
    }

    public class MultiFactorAccessPage
    {
        public string Url { get; set; }
    }
}
