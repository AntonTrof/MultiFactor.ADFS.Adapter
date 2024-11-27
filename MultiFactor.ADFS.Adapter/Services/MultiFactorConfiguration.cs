namespace MultiFactor.ADFS.Adapter.Services
{
    public class MultiFactorConfiguration
    {
        public string ApiKey { get; set; }
        public string ApiSecret { get; set; }
        public string ApiUrl { get; set; }
        public string ApiProxy { get; set; }
        public bool Bypass { get; set; }
        public string Domain { get; set; }
        public string ContextTokenSecret { get; set; }
        public int TokenLifetimeMinutes { get; set; } = 5;
    }
}
