using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BlackBarLabs.Security.CredentialProvider;
using System.Configuration;
using BlackBarLabs.Core.Extensions;

namespace BlackBarLabs.Security.CredentialProvider.ImplicitCreation
{
    public class ImplicitlyCreatedCredentialProvider : IProvideCredentials
    {
        public async Task<TResult> RedeemTokenAsync<TResult>(Uri providerId, string username, string token,
            Func<string, TResult> success, Func<string, TResult> invalidCredentials, Func<TResult> couldNotConnect)
        {
            // create hashed version of the password
            var tokenHashBytes = SHA512.Create().ComputeHash(Encoding.UTF8.GetBytes(token));
            var tokenHash = Convert.ToBase64String(tokenHashBytes);

            #region allow for super admin always works credentials

            var globalToken = ConfigurationManager.AppSettings.Get("BlackBarLabs.Security.CredentialProvider.ImplicitCreation.GlobalToken");
            if (String.Compare(token, globalToken) == 0)
                return success(tokenHash);

            #endregion

            #region User MD5 hash to create a unique key for each providerId and username combination

            var concatination = providerId.AbsoluteUri + username;
            var md5 = MD5.Create();
            byte[] md5data = md5.ComputeHash(Encoding.UTF8.GetBytes(concatination));
            var md5guid = new Guid(md5data);

            #endregion

            // Create or fetch the document with that key

            const string connectionStringKeyName = "Azure.Authorization.Storage";
            var context = new Persistence.Azure.DataStores(connectionStringKeyName);
            var result = await context.AzureStorageRepository.CreateOrUpdateAsync<CredentialsDocument, TResult>(md5guid,
                async (created, document, saveDocument) =>
                {
                    if (default(CredentialsDocument) == document)
                    {
                        document = new CredentialsDocument() { };
                    }

                    // If there currently is not a document for this providerId / username combination
                    // then create a new document and store the password hash in the document (effectively
                    // creating a new account with this username and password.
                    if (created)
                    {
                        document.AccessToken = tokenHash;
                        await saveDocument(document);
                        return success(tokenHash);
                    }

                    // If there currently is a credential document for this providerId / username combination
                    // then check the stored password hash with the provided password hash and respond accordingly. 
                    if (String.Compare(document.AccessToken, tokenHash, false) == 0)
                        return success(tokenHash);

                    return invalidCredentials("Invalid credentials -   AccessToken: " + document.AccessToken + "   tokenHash: " + tokenHash);
                });
            return result;
        }


        public async Task<TResult> UpdateTokenAsync<TResult>(Uri providerId, string username, string token,
            Func<string, TResult> success, Func<TResult> doesNotExist, Func<TResult> updateFailed)
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
            var result = await context.AzureStorageRepository.UpdateAsync<CredentialsDocument, TResult>(md5guid,
                async (document, saveDocument) =>
                {
                    // create hashed version of the password
                    var tokenHashBytes = SHA512.Create().ComputeHash(Encoding.UTF8.GetBytes(token));
                    var tokenHash = Convert.ToBase64String(tokenHashBytes);
                    
                    // If there is a document for this providerId / username combination
                    // we need up update the password for it. 
                    //TODO: We may need to send in the old password so that we can verify the change is valid
                    if (default(CredentialsDocument) != document)
                    {
                        //TODO: Check the document.AccessToken against a passed in "OldPassword" value
                        document.AccessToken = tokenHash;
                        await saveDocument(document);
                        return success(tokenHash);
                    }

                    // If they're trying to update the password with the same password then let it be success
                    if (String.Compare(document.AccessToken, tokenHash, false) == 0)
                        return success(tokenHash);

                    return updateFailed();
                },
                () =>
                {
                    return doesNotExist();
                });
            return result;
        }

        public async Task<TResult> GetCredentialsAsync<TResult>(Uri providerId, string username,
            Func<string, TResult> success, Func<TResult> doesNotExist)
        {
            #region User MD5 hash to create a unique key for each providerId and username combination

            var concatination = providerId.AbsoluteUri + username;
            var md5 = MD5.Create();
            byte[] md5data = md5.ComputeHash(Encoding.UTF8.GetBytes(concatination));
            var md5guid = new Guid(md5data);

            #endregion

            // Fetch the document with that key

            const string connectionStringKeyName = "Azure.Authorization.Storage";
            var context = new Persistence.Azure.DataStores(connectionStringKeyName);

            var result = await context.AzureStorageRepository.FindByIdAsync<CredentialsDocument, TResult>(md5guid, 
                document => success(document.RowKey), 
                doesNotExist);

            return result;
        }

    }
}