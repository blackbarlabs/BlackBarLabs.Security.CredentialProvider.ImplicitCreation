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
            #region User MD5 hash to create a unique key for each providerId and username combination

            var concatination = providerId.AbsoluteUri + username;
            var md5 = MD5.Create();
            byte[] md5data = md5.ComputeHash(Encoding.UTF8.GetBytes(concatination));
            var md5guid = new Guid(md5data);

            #endregion

            // Create or fetch the document with that key

            const string connectionStringKeyName = "Azure.Authorization.Storage";
            var context = new Persistence.Azure.DataStores(connectionStringKeyName);
            var result = await context.AzureStorageRepository.CreateOrUpdateAtomicAsync<TResult, CredentialsDocument>(md5guid,
                async (document, saveDocument) =>
                {
                    // create hashed version of the password
                    var tokenHashBytes = SHA512.Create().ComputeHash(Encoding.UTF8.GetBytes(token));
                    var tokenHash = Convert.ToBase64String(tokenHashBytes);

                    // If there currently is not a document for this providerId / username combination
                    // then create a new document and store the password hash in the document (effectively
                    // creating a new account with this username and password.
                    if (default(CredentialsDocument) == document)
                    {
                        await saveDocument(new CredentialsDocument()
                        {
                            AccessToken = tokenHash,
                        });
                        return success(tokenHash);
                    }

                    // If there currently is a credential document for this providerId / username combination
                    // then check the stored password hash with the provided password hash and respond accordingly. 
                    
                    if (String.Compare(document.AccessToken, tokenHash, false) == 0)
                        return success(tokenHash);

                    return invalidCredentials();
                });
            return result;
        }
    }
}