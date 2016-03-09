using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BlackBarLabs.Security.CredentialProvider;

namespace BlackBarLabs.Security.CredentialProvider.ImplicitCreation
{
    public class ImplicitlyCreatedCredentialProvider : IProvideCredentials
    {
        public async Task<string> RedeemTokenAsync(Uri providerId, string username, string accessToken)
        {
            var concatination = providerId.AbsoluteUri + username;
            var md5 = MD5.Create();
            byte[] md5data = md5.ComputeHash(Encoding.UTF8.GetBytes(concatination));
            var md5guid = new Guid(md5data);
            
            const string connectionStringKeyName = "Azure.Authorization.Storage";
            var context = new BlackBarLabs.Persistence.Azure.DataStores(connectionStringKeyName);
            var result = default(string);
            var updatedDocument = false;
            var saved = await context.AzureStorageRepository.CreateOrUpdateAtomicAsync<CredentialsDocument>(md5guid, (document) =>
            {
                updatedDocument = false; // In case of repeat
                if (string.IsNullOrWhiteSpace(document.AccessToken))
                {
                    result = accessToken;
                    document.AccessToken = accessToken;
                    updatedDocument = true;
                    return Task.FromResult(document);
                }
                if (String.Compare(document.AccessToken, accessToken, false) == 0)
                {
                    result = accessToken;
                }
                return Task.FromResult(default(CredentialsDocument));
            });
            if (updatedDocument && (!saved))
                return default(string); // TODO: Throw exception here?

            return result;
        }
    }
}