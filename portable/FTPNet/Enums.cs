using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FTPNet
{
    public enum DataProtectionMode
    {
        Clear,
        Safe,
        Private
    }

    public enum OSType
    {
        Linux,
        Windows
    }

    public enum SSLMode
    {
        Unencrypted = 0,
        ImplicitSSL = 1,
        ExplicitSSL = 2
    }

    public enum SSLValidationMode
    {
        AcceptAll,
        AskForAll,
    }
    public enum ClientType
    {
        ActiveClient,
        PassiveClient,
    }
}
