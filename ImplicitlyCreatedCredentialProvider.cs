using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BlackBarLabs.Security.CredentialProvider;

namespace BlackBarLabs.Security.CredentialProvider.ImplicitCreation
{
    public class ImplicitlyCreatedCredentialProvider : IProvideCredentials
    {
        public async Task<TResult> RedeemTokenAsync<TResult>(Uri providerId, string username, string token,
            Func<string, TResult> success, Func<TResult> invalidCredentials, Func<TResult> couldNotConnect)
        {
            var concatination = providerId.AbsoluteUri + username;
            var md5 = MD5.Create();
            byte[] md5data = md5.ComputeHash(Encoding.UTF8.GetBytes(concatination));
            var md5guid = new Guid(md5data);
            
            const string connectionStringKeyName = "Azure.Authorization.Storage";
            var context = new Persistence.Azure.DataStores(connectionStringKeyName);

            var result = await context.AzureStorageRepository.CreateOrUpdateAtomicAsync<TResult, CredentialsDocument>(md5guid,
                async (document, saveDocument) =>
                {
                    var tokenHashBytes = SHA512.Create().ComputeHash(Encoding.UTF8.GetBytes(token));
                    var tokenHash = Convert.ToBase64String(tokenHashBytes);
                    if (default(CredentialsDocument) == document)
                    {
                        await saveDocument(new CredentialsDocument()
                        {
                            AccessToken = tokenHash,
                        });
                        return success(tokenHash);
                    }

                    if (String.Compare(document.AccessToken, tokenHash, false) == 0)
                        return success(tokenHash);

                    return invalidCredentials();
                });
            return result;
        }
    }
}