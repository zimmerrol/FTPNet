using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace FTPNet
{
    public class FTP
    {
        public delegate void CommandSendEventHandler(string command);
        public delegate void AnswerReadEventHandler(string answer);
        public delegate void ConnectedEventHandler();
        public delegate void DisconnectedEventHandler();
        public delegate void LoggedInEventHandler();
        public delegate bool CertifacteValidationEventHandler(System.Security.Cryptography.X509Certificates.X509Certificate certificate, System.Security.Cryptography.X509Certificates.X509Chain chain, SslPolicyErrors sslPolicyErrors);

        public event CommandSendEventHandler CommandSendEvent;
        public event AnswerReadEventHandler AnswerReadEvent;
        public event ConnectedEventHandler ConnectedEvent;
        public event DisconnectedEventHandler DisconnectedEvent;
        public event LoggedInEventHandler LoggedInEvent;
        public event CertifacteValidationEventHandler CertifacteValidationEvent;

        public bool LogInAutomatic = true;
        public bool EnterPassiveModeAutomatic = true;
        public bool LoggedIn = false;
        public int ConnectionAttemps { get; set; } = 2;
        public List<string> SupportedCommands { get; set; }

        public string Username { get; set; }
        public string Password { get; set; }
        public string Server { get; set; }
        private string realServer { get; set; }
        public int Port { get; set; }
        public OSType OS { get; set; }

        public TcpClient ActiveClient { get; set; }
        public TcpClient PassiveClient { get; set; }

        public StreamWriter ActiveClientWriter { get; set; }
        public BinaryWriter PassiveClientWriter { get; set; }

        public BinaryReader ActiveClientReader { get; set; }
        public BinaryReader PassiveClientReader { get; set; }

        private SSLMode _encryptionModeValue;
        public SSLMode EncryptionMode
        {
            get
            {
                return _encryptionModeValue;
            }
            set
            {
                _encryptionModeValue = value;

                if (value == SSLMode.ExplicitSSL)
                    _useExplicitSSL();

                if (value == SSLMode.ImplicitSSL)
                    _protectionMode = DataProtectionMode.Private;
            }
        }

        public SSLValidationMode ValidationMode { get; set; }

        private int _connectionTypeValue;
        public int ConnectionType
        {
            get
            {
                return _connectionTypeValue;
            }
            set
            {
                _connectionTypeValue = value;
                if (value == 530)
                    if (LogInAutomatic)
                        Login();
            }
        }

        private Stream _activeClientStream { get; set; }
        private Stream _passiveClientStream { get; set; }

        public FTP()
        {
            SupportedCommands = new List<string>();
        }

        #region Methods
        public bool IsNumeric(string input)
        {
            int helper;
            return int.TryParse(input, out helper);
        }

        private DataProtectionMode _protectionMode { get; set; }

        public bool ChangeProtectionMode(DataProtectionMode protectionMode)
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("PBSZ 0");

            if (ConnectionType != 200)
                return false;

            string command = "PROT ";

            if (protectionMode == DataProtectionMode.Clear)
                command += "C";
            else if (protectionMode == DataProtectionMode.Private)
                command += "P";
            else
                command += "S";

            answer = SendCommandReadAnswer(command);

            bool res = ConnectionType == 200;

            if (res)
                _protectionMode = protectionMode;

            return res;
        }

        public enum DataProtectionMode
        {
            Clear,
            Safe,
            Private
        }

        public bool Login()
        {
            string answer = "";
            LogInAutomatic = false;

            answer = SendCommandReadAnswer("USER " + Username);

            if (ConnectionType == 331)
                answer = SendCommandReadAnswer("PASS " + Password, null, "230");

            if (ConnectionType == 230)
            {

                LoggedIn = true;
                if (LoggedInEvent != null)
                    LoggedInEvent();
                LogInAutomatic = true;
                return true;
            }

            return false;
        }

        public void Disconnect()
        {
            if (ActiveClient != null && ActiveClient.Connected)
            {
                ActiveClient.Close();
                ActiveClient = null;
            }

            if (PassiveClient != null && PassiveClient.Connected)
            {
                PassiveClient.Close();
                PassiveClient = null;
            }
        }

        public bool Connect()
        {
            ActiveClient = new TcpClient();

            for (int connectionTries = 0; connectionTries < ConnectionAttemps; connectionTries++)
            {
                if (Port == 0)
                    Port = 21;

                realServer = Server.ToLower();

                if (realServer.StartsWith("ftp://"))
                    realServer = Server.Remove(0, 6);
                if (realServer.StartsWith("ftps://"))
                    realServer = Server.Remove(0, 7);
                else if (realServer.StartsWith("http://"))
                    realServer = Server.Remove(0, 7);

                if (realServer.LastIndexOf(":") != -1)
                {
                    if (realServer.Length > realServer.LastIndexOf(":") && IsNumeric(realServer.Substring(realServer.LastIndexOf(":") + 1)))
                    {
                        int PortValue = 21;

                        int.TryParse(realServer.Substring(Server.LastIndexOf(":") + 1), out PortValue);

                        realServer = Server.Remove(realServer.Length - (PortValue.ToString().Length + 1));


                        Port = PortValue;
                    }
                }

                if (_connectClient(realServer, Port, ActiveClient))
                {
                    _activeClientStream = ActiveClient.GetStream();

                    if (EncryptionMode == SSLMode.ImplicitSSL)
                        _useImplicitSSL();

                    ActiveClientWriter = new StreamWriter(_activeClientStream);
                    ActiveClientReader = new BinaryReader(_activeClientStream);

                    if (ActiveClient != null)
                    {
                        string answer = ReadAnswer(null, "220");
                        if (answer.StartsWith("220"))
                        {
                            if (ConnectedEvent != null)
                                ConnectedEvent();
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private void _useExplicitSSL()
        {
            if (!SupportedCommands.Contains("AUTH TLS"))
                return;

            if (ActiveClient != null)
            {
                string answer = SendCommandReadAnswer("AUTH TLS");

                if (ConnectionType == 234)
                {
                    SslStream sslStream = new SslStream(ActiveClient.GetStream(), false, _validateServerCertificate);

                    sslStream.AuthenticateAsClient(realServer);
                    _activeClientStream = sslStream;
                    ActiveClientReader = new BinaryReader(_activeClientStream);
                    ActiveClientWriter = new StreamWriter(_activeClientStream);
                }
            }
        }

        private void _useImplicitSSL()
        {
            if (ActiveClient != null)
            {
                if (ConnectionType == 0)
                {
                    SslStream sslStream = new SslStream(ActiveClient.GetStream(), false, _validateServerCertificate);

                    sslStream.AuthenticateAsClient(realServer);
                    _activeClientStream = sslStream;
                    ActiveClientReader = new BinaryReader(_activeClientStream);
                    ActiveClientWriter = new StreamWriter(_activeClientStream);
                }
            }
        }

        private bool _validateServerCertificate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate, System.Security.Cryptography.X509Certificates.X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (_certificateAccepted)
                return true;

            switch (ValidationMode)
            {
                case SSLValidationMode.AcceptAll:
                    return true;
                case SSLValidationMode.AcceptOnlyValids:
                    switch (sslPolicyErrors)
                    {
                        case SslPolicyErrors.None:
                            _certificateAccepted = true;
                            return true;
                        default:
                            return false;
                    }

                case SSLValidationMode.AskForInvalids:
                    switch (sslPolicyErrors)
                    {
                        case SslPolicyErrors.None:
                            _certificateAccepted = true;
                            return true;
                        default:
                            if (CertifacteValidationEvent != null)
                            {
                                bool res = CertifacteValidationEvent(certificate, chain, sslPolicyErrors);
                                _certificateAccepted = res;
                                return res;
                            }
                            else
                                return false;
                    }
            }

            return true;
        }

        public void GetOS()
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("SYST");

            OS = answer.ToLower().Contains("windows") ? OSType.Windows : OSType.Linux;
        }

        public bool TryToEnterSSL()
        {
            _checkConnected();

            return true;
        }

        public bool MakeDirectory(string name)
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("MKD " + name);

            return (ConnectionType == 227);
        }

        public bool ChangeWorkingDirectory(string name)
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("CWD " + name);

            return (ConnectionType == 227);
        }

        public bool DeleteFile(string name)
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("DELE " + name);

            return (ConnectionType == 227);
        }

        public bool RemoveDirectory(string name)
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("RMD " + name);

            return (ConnectionType == 227);
        }

        public bool RenameFile(string oldName, string newName)
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("RNFR " + oldName);

            if (ConnectionType != 350)
                return false;

            answer = SendCommandReadAnswer("RNTO " + newName);

            return (ConnectionType == 227);
        }

        private bool _connectClient(string address, int port, TcpClient client)
        {
            try
            {
                client.Connect(address, port);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private bool _certificateAccepted = false;

        public bool EnterPassiveMode()
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("PASV");

            if (ConnectionType != 227)
                return false;

            answer = answer.Substring(answer.IndexOf('(') + 1, answer.LastIndexOf(')') - answer.LastIndexOf('(') - 1).Trim();
            string[] parts = answer.Split(',');
            string ip = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3];
            int port = int.Parse(parts[4]) * 256 + int.Parse(parts[5]);

            PassiveClient = new TcpClient();

            bool res = _connectClient(ip, port, PassiveClient);

            if (res)
            {
                if (_protectionMode == DataProtectionMode.Private)
                {
                    SslStream sslStream = new SslStream(PassiveClient.GetStream(), false, _validateServerCertificate);
                    sslStream.AuthenticateAsClient(realServer);
                    PassiveClientReader = new BinaryReader(sslStream);
                    PassiveClientWriter = new BinaryWriter(sslStream);
                }
            }

            return res;
        }

        public bool EnterBinaryMode()
        {
            _checkConnected();

            for (int i = 0; i < 2; i++)
            {
                SendCommandReadAnswer("TYPE I");
                if (ConnectionType == 227)
                    return true;
                else if (ConnectionType == 421)
                    Login();
            }

            return false;
        }

        public bool EnterASCIIMode()
        {
            _checkConnected();

            SendCommandReadAnswer("TYPE A");

            return (ConnectionType == 227);
        }

        //private void CheckLoggedIn()
        //{
        //    SendCommandReadAnswer("NOOP");

        //    if (ConnectionType == 421)
        //    {
        //        Connect();
        //        Login();
        //    }
        //}

        public bool UploadFile(string name, byte[] buffer, bool binaryMode = false)
        {
            _checkConnected();

            if (PassiveClient == null)
                if (EnterPassiveModeAutomatic)
                    EnterPassiveMode();

            if (binaryMode)
                EnterBinaryMode();

            string answer = SendCommandReadAnswer("STOR " + name);

            if (answer.Trim().StartsWith("425"))
            {
                PassiveClient = null;
                if (EnterPassiveModeAutomatic)
                {
                    EnterPassiveMode();
                    answer = SendCommandReadAnswer("STOR " + name);
                }
            }

            if (answer.Trim().StartsWith("150") | answer.Trim().StartsWith("125"))
            {
                return _uploadData(buffer);
            }

            return false;
        }

        public bool UploadFileWithUniqueName(byte[] buffer, bool binaryMode = false)
        {
            _checkConnected();

            if (PassiveClient == null)
                if (EnterPassiveModeAutomatic)
                    EnterPassiveMode();

            if (binaryMode)
                EnterBinaryMode();

            string answer = SendCommandReadAnswer("STOU");

            if (answer.Trim().StartsWith("425"))
            {
                PassiveClient = null;
                if (EnterPassiveModeAutomatic)
                {
                    EnterPassiveMode();
                    answer = SendCommandReadAnswer("STOU");
                }
            }

            if (answer.Trim().StartsWith("150") & answer.Trim().StartsWith("125"))
            {
                return _uploadData(buffer);
            }

            return false;
        }

        private bool _uploadData(byte[] buffer)
        {
            long writtenBytes = 0;

            for (int i = 0; i < buffer.Length; i += 1024)
            {
                writtenBytes = i + 1023;

                if (writtenBytes > buffer.Length)
                    writtenBytes = buffer.Length - 1;

                for (int j = i; j <= writtenBytes; j++)
                {
                    PassiveClientWriter.Write(buffer[j]);
                }

                PassiveClientWriter.Flush();
            }

            PassiveClient.Close();
            PassiveClient = null;

            string answer = ReadAnswer();

            EnterASCIIMode();

            return answer.Trim().StartsWith("226");
        }

        public string PrintWorkingDirectory()
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("PWD");

            if (answer.Trim().StartsWith("257"))
                return answer.Remove(0, 5).Substring(0, answer.LastIndexOf(Char.ConvertFromUtf32(34)) - 5);

            return "";
        }

        public bool ChangePermission(string name, string permissions)
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("SITE CHMOD " + permissions + " " + name);
            return (ConnectionType == 200);
        }

        private void _checkConnected()
        {
            if (!(ActiveClient != null && ActiveClient.Connected))
            {
                Connect();

                //set the value again to archive the encryption again
                if (EncryptionMode == SSLMode.ExplicitSSL)
                    EncryptionMode = SSLMode.ExplicitSSL;

                Login();
            }
        }

        public void GetSupportedCommands()
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("FEAT", null, "211");

            foreach (string item in answer.Split('\n'))
            {
                if (item.Trim().Length > 0 && !item.Trim().StartsWith("211"))
                    SupportedCommands.Add(item.Trim());
            }
        }

        public bool UseUTF8()
        {
            if (SupportedCommands.Contains("UTF8"))
            {
                SendCommandReadAnswer("OPTS UTF8 ON");

                if (ConnectionType == 200)
                    return true;
            }
            return false;
        }

        public bool SendCommand(string command, TcpClient client = null)
        {
            if (client == null)
                client = ActiveClient;

            if (client == null)
            {
                if (DisconnectedEvent != null)
                    DisconnectedEvent();
                return false;
            }

            StreamWriter writer;

            command = command.Trim();

            _checkConnected();

            if (client == ActiveClient)
            {
                if (ActiveClientWriter == null)
                    ActiveClientWriter = new StreamWriter(_activeClientStream);
                writer = ActiveClientWriter;
            }
            else
            {
                if (PassiveClientWriter == null)
                    PassiveClientWriter = new BinaryWriter(client.GetStream());
                writer = new StreamWriter(PassiveClientWriter.BaseStream);
            }

            writer.WriteLine(command);
            writer.Flush();

            if (command.ToLower().StartsWith("pass "))
                command = "PASS **********\n";
            if (command.ToLower() != "noop")
                if (CommandSendEvent != null)
                    CommandSendEvent(command);

            return true;
        }

        public string ReadAnswer(TcpClient client = null, string WaitForStatusCode = "000", bool PrintOutput = true)
        {
            if (client == null)
                client = ActiveClient;

            BinaryReader reader = null;

            if (client != null)
            {
                if (client == ActiveClient)
                {
                    if (ActiveClientReader == null)
                        ActiveClientReader = new BinaryReader(_activeClientStream);
                    reader = ActiveClientReader;
                }
                else
                {
                    if (PassiveClientReader == null)
                        PassiveClientReader = new BinaryReader(client.GetStream());
                    reader = PassiveClientReader;
                }
            }

            string answer = "";

            byte[] buffer = new byte[1024];
            int read = 1024;

            while (read == buffer.Length)
            {
                try
                {
                    read = reader.Read(buffer, 0, 1024);
                }
                catch (IOException)
                {
                    _checkConnected();
                    //make the connection look interupted for the check routine in the read & send method
                    ConnectionType = 421;
                    return "";
                }

                answer += System.Text.Encoding.UTF8.GetString(buffer, 0, read);
                buffer = new byte[1024];
            }

            if (client == ActiveClient && answer.Length >= 3)
            {
                if (WaitForStatusCode != "000")
                {
                    string answerTmp = answer;

                    List<string> tmpLines = new List<string>(answer.Split('\n'));

                    string lastAnswerLine = tmpLines[tmpLines.Count - 1].Trim();

                    if (string.IsNullOrEmpty(lastAnswerLine))
                    {
                        if (tmpLines.Count - 2 >= 0)
                            lastAnswerLine = tmpLines[tmpLines.Count - 2];

                        answerTmp = lastAnswerLine.Trim();

                        while (answer.StartsWith(WaitForStatusCode, StringComparison.CurrentCultureIgnoreCase) == true && answerTmp.StartsWith(WaitForStatusCode + " ", StringComparison.CurrentCultureIgnoreCase) == false)
                        {
                            answerTmp = ReadAnswer(client, "000", false).Trim();
                            answer += answerTmp + "\n";
                            answerTmp = answerTmp.Split('\n')[answerTmp.Split('\n').Length - 1].Trim();
                            tmpLines.Add(answerTmp);
                        }

                        answer = answer.Trim();
                    }
                }

                int type;
                Int32.TryParse(answer.Substring(0, 3), out type);
                if (type != 0)
                    ConnectionType = type;
                //if (type == 421)
                //    Login();
            }

            if (PrintOutput)
            {
                string[] answers = answer.Split('\n');
                foreach (string item in answers)
                {
                    if (item.Trim().Length > 1 && item.Contains("NOOP") == false)
                        if (AnswerReadEvent != null)
                            AnswerReadEvent(item);
                }
            }

            return answer;
        }

        public string SendCommandReadAnswer(string command, TcpClient client = null, string WaitForStatusCode = "000")
        {
            for (int i = 0; i < 2; i++)
            {
                SendCommand(command, client);
                string res = ReadAnswer(null, WaitForStatusCode);
                if (ConnectionType != 421)
                    return res;
            }

            return "";
        }

        public List<IOElement> ListFiles()
        {
            _checkConnected();

            string answer = SendCommandReadAnswer("LIST");

            string passiveAnswer = ReadAnswer(PassiveClient, "000", false).Trim();

            //dispose passive objects
            PassiveClient.Close();
            PassiveClient = null;
            PassiveClientReader.Close();
            PassiveClientReader = null;

            if (answer.Contains("226") == false)
                answer = ReadAnswer();

            List<IOElement> Files = new List<IOElement>();

            if (passiveAnswer.Length == 0)
                return Files;

            //detect os for file listing parsing
            int os = 0;
            string[] osHelper = passiveAnswer.Split('\n');

            if (osHelper.Length > 0)
            {
                os = (osHelper[0][10] == ' ' && osHelper[0][9] != ' ') ? 0 : 1;
            }

            Files = ((OS & (OSType)os) == OSType.Windows) ? IOElement.ParseWindowsFiles(passiveAnswer) : IOElement.ParseLinuxFiles(passiveAnswer);

            Files.Sort();
            return Files;
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
            AcceptOnlyValids,
            AskForInvalids
        }
        #endregion
    }

    //enum Commands
    //{
    //    ABOR,
    //    CWD,
    //    DELE,
    //    LIST,
    //    MDTM,
    //    MKD,
    //    NLST,
    //    PASS,
    //    PASV,
    //    PORT,
    //    PWD,
    //    QUIT,
    //    RETR,
    //    FEAT,
    //    RMD,
    //    RNFR,
    //    RNTO,
    //    SITE,
    //    SIZE,
    //    STOR,
    //    TYPE,
    //    USER,
    //    ACCI,
    //    APPE,
    //    CDUP,
    //    HELP,
    //    MLSD,
    //    MODE,
    //    NOOP,
    //    REIN,
    //    STAT,
    //    STOU,
    //    STRU,
    //    SYST
    //}
}
