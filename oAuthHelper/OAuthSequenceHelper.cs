using System;
using System.Net;
using System.Threading;
using System.Web;

namespace oAuthHelper
{
    public class OAuthSequenceHelper<TClient, TRequestToken, TAccessToken>
    {
        public delegate string GenerateAuthUrl(TClient client, TRequestToken requestToken);
        public delegate TRequestToken RequestTokenRequest(TClient client);
        public delegate TAccessToken ListenerGotRequest(TClient client, TRequestToken requestToken, string verifierCode);


        public event GenerateAuthUrl GenerateAuthUrlEvent;
        public event ListenerGotRequest ListenerGotRequestEvent;
        public event RequestTokenRequest RequestTokenRequestEvent;


        private const string ResponseString = "<HTML><BODY>You can close the page now</BODY></HTML>"; // a very basic response to show to a user upon successful authorization
        protected ManualResetEvent Done { get; set; }        
        public TAccessToken ResultingToken;
        private TRequestToken _requestToken;        
        protected TClient Client { get; private set; }
        protected string HttpCallbackUrl { get; private set; }
        protected string VerifierParameterName { get; private set; }

        public OAuthSequenceHelper(TClient client)
        {
            Client = client;
            Done = new ManualResetEvent(false);
        }

        public OAuthSequenceHelper(TClient client, string httpCallbackUrl = "http://127.0.0.1:64646/callback/", string verifierParameterName = "oauth_verifier")
        {
            Client = client;
            HttpCallbackUrl = httpCallbackUrl;
            VerifierParameterName = verifierParameterName;            
        }

        public string OAuth_StepOne()
        {
            _requestToken = OnRequestTokenRequest();
            return OnGenerateAuthUrlEvent(_requestToken);
        }

        public TAccessToken OAuth_StepTwo()
        {
            ThreadPool.QueueUserWorkItem(ProcessCallback, this);
            var count = 0; // we'll count how long the process can wait. 4 mins seems more than enough
            do
            {
                count++;
            } while (!WaitHandle.WaitAll(new WaitHandle[] { this.Done }, 5000) || count < 48);

            if (this.ResultingToken == null)
                throw new Exception("Timed out waiting for oAuth callback. Try again");
            
            return this.ResultingToken;
        }

        protected virtual string OnGenerateAuthUrlEvent(TRequestToken requestToken)
        {
            if (GenerateAuthUrlEvent != null) 
                return GenerateAuthUrlEvent(Client, requestToken);
            throw new ArgumentException("OAuthSequenceHelper needs a GenerateAuthUrlEvent defined");
        }

        protected virtual TAccessToken OnListenerGotRequest(string verifierCode)
        {
            if (ListenerGotRequestEvent != null) 
                return ListenerGotRequestEvent(Client, _requestToken, verifierCode);
            throw new ArgumentException("OAuthSequenceHelper needs a ListenerGotRequestEvent defined");
        }

        protected virtual TRequestToken OnRequestTokenRequest()
        {
            if (RequestTokenRequestEvent != null) 
                return RequestTokenRequestEvent(Client);            
            throw new ArgumentException("OAuthSequenceHelper needs a RequestTokenRequestEvent defined");
        }

        private void ProcessCallback(object listenerContext)
        {       
            OAuthSequenceHelper<TClient, TRequestToken, TAccessToken> authSequenceHelper = null;
            authSequenceHelper = listenerContext as OAuthSequenceHelper<TClient, TRequestToken, TAccessToken>;
            if (authSequenceHelper == null) throw new ArgumentNullException("listenerContext");
            try
            {
                using (var listener = new HttpListener())
                {
                    listener.Prefixes.Add(authSequenceHelper.HttpCallbackUrl);
                    listener.Start();                
                    var context = listener.GetContext();// this call would block until request is made
                    if (context.Request.Url == null)
                        throw new HttpParseException("Request URL is empty");
                    var token = HttpUtility.ParseQueryString(context.Request.RawUrl)[authSequenceHelper.VerifierParameterName];
                    lock (authSequenceHelper)
                    {
                        authSequenceHelper.ResultingToken = OnListenerGotRequest(token);
                    }
                    
                    var response = context.Response;
                    var buffer = System.Text.Encoding.UTF8.GetBytes(ResponseString);
                    // Get a response stream and write the response to it.
                    response.ContentLength64 = buffer.Length;
                    using (var output = response.OutputStream)
                    {
                        output.Write(buffer, 0, buffer.Length);
                        output.Close();//must close the output stream.
                    }
                    listener.Stop();
                }
            }
            finally
            {
                lock (authSequenceHelper)
                {
                    authSequenceHelper.Done.Set(); // set the event so waiting thread knows we're done    
                }
            }
        }        
    }
}
