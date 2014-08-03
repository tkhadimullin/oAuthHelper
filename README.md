oAuthHelper
===========

A library that takes away some complexity of the protocol

##Usage

```C#
		/***/
           var _client = new OAuthClient(appKey, appSecret);

           var _oAuthHelper = new OAuthSequenceHelper<OAuthClient, OAuthRequestToken, OAuthAccessToken>(_client, "http://127.0.0.1:64646/callback/");
           _oAuthHelper.RequestTokenRequestEvent += oAuthHelper_RequestTokenRequestEvent;
           _oAuthHelper.GenerateAuthUrlEvent += OAuthHelper_GenerateAuthUrlEvent;
           _oAuthHelper.ListenerGotRequestEvent += OAuthHelperOnListenerGotRequestEvent;           
		   // do the actual authentication
		   Process.Start(_oAuthHelper.OAuth_StepOne()); // open user's browser and point it to the service's authorization page
           return _oAuthHelper.OAuth_StepTwo();//this call would block until user authorizes the application.
       
		/***/
       private OAuthAccessToken OAuthHelperOnListenerGotRequestEvent(OAuthClient client, OAuthRequestToken requestToken, string verifierCode)
       {
           return client.OAuthGetAccessToken(requestToken, verifierCode);
       }

       OAuthRequestToken oAuthHelper_RequestTokenRequestEvent(OAuthClient client)
       {
           return client.OAuthGetRequestToken("http://127.0.0.1:64646/callback/");
       }

       string OAuthHelper_GenerateAuthUrlEvent(OAuthClient client, OAuthRequestToken requestToken)
       {
           var token = requestToken.Token;
           return client.OAuthCalculateAuthorizationUrl(token, AuthLevel.Delete);
       }
    }
```