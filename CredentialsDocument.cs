namespace BlackBarLabs.Security.CredentialProvider.ImplicitCreation
{
    internal class CredentialsDocument : Microsoft.WindowsAzure.Storage.Table.TableEntity
    {
        public string AccessToken { get; set; }
    }
}
