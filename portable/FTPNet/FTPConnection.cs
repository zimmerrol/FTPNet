using Org.BouncyCastle.Crypto.Tls;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;

namespace FTPNet
{
    public class FTPConnection
    {
        public FTPConnection(string userName, string password, HostName server, string port, FTPClient parentClient)
        {
            _username = userName;
            _password = password;
            _server = server;
            _port = port;
            _parentClient = parentClient;
            IsIdled = true;
        }

        #region Events
        public event CommandSendEventHandler CommandSendEvent;
        public event AnswerReadEventHandler AnswerReadEvent;
        public event ConnectedEventHandler ConnectedEvent;
        public event DisconnectedEventHandler DisconnectedEvent;
        public event LoggedInEventHandler LoggedInEvent;
        public event CertifacteValidationEventHandler CertifacteValidationEvent;
        public event EventHandler<string> CurrentWorkingDirectoryChangedEvent;
        #endregion

        #region Fields
        private string _username;
        private string _password;
        private HostName _server;
        private string _port;
        private System.Text.Encoding _encoding = Encoding.UTF8;

        private FTPClient _parentClient;

        private StreamSocket _controlChannelSocket;
        private BinaryWriter _controlChannelSocketWriter;
        private BinaryReader _controlChannelSocketReader;
        private TlsProtocolHandler _controlChannelSocketTlsProtocolHandler;

        private StreamSocket _dataChannelSocket;
        private BinaryWriter _dataChannelSocketWriter;
        private BinaryReader _dataChannelSocketReader;
        private TlsProtocolHandler _dataChannelSocketTlsProtocolHandler;

        public bool IsIdled { get; private set; }

        public bool LogInAutomatic = true;
        public bool EnterPassiveModeAutomatic = true;
        public bool LoggedIn { get; set; }

        public SSLMode EncryptionMode { get; set; }
        public DataProtectionMode ProtectionMode { get; set; }

        private int _connectionType;
        public int ConnectionType
        {
            get
            {
                return _connectionType;
            }
            set
            {
                _connectionType = value;
                if (value == 530)
                    if (LogInAutomatic)
                        Login();
            }
        }

        private int _connectionAttemps = 2;
        public int ConnectionAttemps
        {
            get
            {
                return _connectionAttemps;
            }
            set
            {
                _connectionAttemps = value;
            }
        }

        private string _currentWorkingDirectory;
        public string CurrentWorkingDirectory
        {
            get
            {
                return _currentWorkingDirectory;
            }
            set
            {
                _currentWorkingDirectory = value;
                if (CurrentWorkingDirectoryChangedEvent != null)
                    CurrentWorkingDirectoryChangedEvent(this, CurrentWorkingDirectory);
            }

        }
        public bool IsDisconnected { get; private set; }
        #endregion

        #region Methods
        public bool ChangeProtectionMode(DataProtectionMode protectionMode)
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("PBSZ 0", out answer))
            {
                return false;
            }

            if (answer == null)
                return false;

            if (ConnectionType != 200)
                return false;

            string command = "PROT ";

            if (protectionMode == DataProtectionMode.Clear)
                command += "C";
            else if (protectionMode == DataProtectionMode.Private)
                command += "P";
            else
                command += "S";

            if (!TrySendCommandReadAnswer(command, out answer))
            {
                return false;
            }

            if (answer == null)
                return false;

            return ConnectionType == 200;
        }

        public bool Login()
        {
            //enter Explicit encryption if necessary
            if (_parentClient.EncryptionMode == SSLMode.ExplicitSSL)
            {
                UseExplicitSSL();
                ChangeProtectionMode(ProtectionMode);
            }

            string answer = string.Empty;
            LogInAutomatic = false;

            if (!TrySendCommandReadAnswer("USER " + _username, out answer))
            {
                return false;
            }

            if (answer == null)
                return false;

            if (ConnectionType == 331)
            {
                if (!TrySendCommandReadAnswer("PASS " + _password, out answer))
                {
                    return false;
                }

                if (answer == null)
                    return false;
            }
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
            if (_controlChannelSocket != null)
            {
                _controlChannelSocket.Dispose();
                _controlChannelSocket = null;
            }

            if (_dataChannelSocket != null)
            {
                _dataChannelSocket.Dispose();
                _dataChannelSocket = null;
            }
        }

        public async Task<bool> Connect()
        {
            _controlChannelSocket = new StreamSocket();
            if (await ConnectClient(_server, _port, _controlChannelSocket))
            {
                if (_parentClient.EncryptionMode == SSLMode.ImplicitSSL)
                {
                    UseImplicitSSL();
                    ChangeProtectionMode(ProtectionMode);
                }

                _controlChannelSocketWriter = new BinaryWriter(_controlChannelSocket.OutputStream.AsStreamForWrite());
                _controlChannelSocketReader = new BinaryReader(_controlChannelSocket.InputStream.AsStreamForRead());

                string answer = string.Empty;
                try
                {
                    answer = ReadAnswer(ClientType.ActiveClient);
                }
                catch (IOException)
                {
                    return false;
                }

                if (answer.StartsWith("220"))
                {
                    IsDisconnected = false;
                    if (ConnectedEvent != null)
                        ConnectedEvent();

                    return true;
                }
            }
            return false;
        }

        private void UseExplicitSSL()
        {
            if (_controlChannelSocket != null)
            {
                string answer;
                if (!TrySendCommandReadAnswer("AUTH TLS", out answer))
                {
                    return;
                }
                if (answer == null)
                    return;

                if (ConnectionType == 234)
                {
                    _controlChannelSocketTlsProtocolHandler = new TlsProtocolHandler(_controlChannelSocket.InputStream.AsStreamForRead(), _controlChannelSocket.OutputStream.AsStreamForWrite());
                    _controlChannelSocketTlsProtocolHandler.Connect(_parentClient.CertificateVerifyer);

                    _controlChannelSocketWriter = new BinaryWriter(_controlChannelSocketTlsProtocolHandler.Stream);
                    _controlChannelSocketReader = new BinaryReader(_controlChannelSocketTlsProtocolHandler.Stream);
                }
            }
        }

        private void UseImplicitSSL()
        {
            if (_controlChannelSocket != null)
            {
                if (ConnectionType == 0)
                {
                    _controlChannelSocketTlsProtocolHandler = new TlsProtocolHandler(_controlChannelSocket.InputStream.AsStreamForRead(), _controlChannelSocket.OutputStream.AsStreamForWrite());
                    _controlChannelSocketTlsProtocolHandler.Connect(_parentClient.CertificateVerifyer);

                    _controlChannelSocketWriter = new BinaryWriter(_controlChannelSocketTlsProtocolHandler.Stream);
                    _controlChannelSocketReader = new BinaryReader(_controlChannelSocketTlsProtocolHandler.Stream);
                }
            }
        }

        public void GetOS()
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("SYST", out answer))
            {
                return;
            }
            if (answer == null)
                return;

            _parentClient.OS = answer.ToLower().Contains("windows") ? OSType.Windows : OSType.Linux;
        }

        public bool TryToEnterSSL()
        {
            checkConnected();

            return true;
        }

        public bool MakeDirectory(string name)
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("MKD " + name, out answer))
            {
                return false;
            }

            if (answer == null)
                return false;

            return (ConnectionType == 227);
        }

        public bool ChangeWorkingDirectory(string name)
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("CWD " + name, out answer))
            {
                return false;
            }
            if (answer == null)
                return false;

            PrintWorkingDirectory();
            bool success = (ConnectionType == 227);
            return success;
        }

        public bool DeleteFile(string name)
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("DELE " + name, out answer))
            {
                return false;
            }
            if (answer == null)
                return false;

            return (ConnectionType == 227);
        }

        public bool RemoveDirectory(string name)
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("RMD " + name, out answer))
            {
                return false;
            }

            if (answer == null)
                return false;

            return (ConnectionType == 227);
        }

        public bool RenameFile(string oldName, string newName)
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("RNFR " + oldName, out answer))
            {
                return false;
            }

            if (answer == null)
                return false;

            if (ConnectionType != 350)
                return false;

            if (!TrySendCommandReadAnswer("RNTO " + newName, out answer))
            {
                return false;
            }

            if (answer == null)
                return false;

            return (ConnectionType == 227);
        }

        public async Task<bool> EnterPassiveMode()
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("PASV", out answer))
            {
                return false;
            }

            if (answer == null)
                return false;

            if (ConnectionType != 227)
                return false;

            answer = answer.Substring(answer.IndexOf('(') + 1, answer.LastIndexOf(')') - answer.LastIndexOf('(') - 1).Trim();
            string[] parts = answer.Split(',');
            string ip = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3];
            int port = int.Parse(parts[4]) * 256 + int.Parse(parts[5]);

            _dataChannelSocket = new StreamSocket();

            bool res = await ConnectClient(_server, port.ToString(), _dataChannelSocket);

            if (res)
            {
                if (_parentClient.ProtectionMode == DataProtectionMode.Private)
                {
                    try
                    {
                        _dataChannelSocketTlsProtocolHandler = new TlsProtocolHandler(_dataChannelSocket.InputStream.AsStreamForRead(), _dataChannelSocket.OutputStream.AsStreamForWrite());
                        _dataChannelSocketTlsProtocolHandler.Connect(_parentClient.CertificateVerifyer);

                        _dataChannelSocketWriter = new BinaryWriter(_dataChannelSocketTlsProtocolHandler.Stream);
                        _dataChannelSocketReader = new BinaryReader(_dataChannelSocketTlsProtocolHandler.Stream);
                    }
                    catch (Exception)
                    {
                        throw;
                    }
                }
                else
                {
                    _dataChannelSocketReader = new BinaryReader(_dataChannelSocket.InputStream.AsStreamForRead());
                    _dataChannelSocketWriter = new BinaryWriter(_dataChannelSocket.OutputStream.AsStreamForWrite());
                }
            }

            return res;
        }
        public string PrintWorkingDirectory()
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("PWD", out answer))
            {
                return string.Empty;
            }
            if (answer == null)
                return string.Empty;

            if (answer.Trim().StartsWith("257"))
            {
                CurrentWorkingDirectory = answer.Remove(0, 5).Substring(0, answer.LastIndexOf(Char.ConvertFromUtf32(34)) - 5);
                return CurrentWorkingDirectory;
            }

            return string.Empty;
        }

        public bool ChangePermission(string name, string permissions)
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("SITE CHMOD " + permissions + " " + name, out answer))
            {
                return false;
            }
            if (answer == null)
                return false;

            return (ConnectionType == 200);
        }

        private async void checkConnected()
        {
            if (!(_controlChannelSocketWriter != null))
            {
                await Connect();

                //set the value again to archive the encryption again
                if (_parentClient.EncryptionMode == SSLMode.ExplicitSSL)
                    _parentClient.EncryptionMode = SSLMode.ExplicitSSL;

                Login();
            }
        }

        public void GetSupportedCommands()
        {
            checkConnected();

            string answer;
            if (!TrySendCommandReadAnswer("FEAT", out answer))
            {
                return;
            }

            if (answer == null)
                return;

            foreach (string item in answer.Split('\n'))
            {
                if (item.Trim().Length > 0 && !item.Trim().StartsWith("211"))
                    _parentClient.SupportedCommands.Add(item.Trim());
            }
        }

        public async Task<List<IOElement>> ListFiles()
        {
            return await ListFiles(string.Empty);
        }

        public async Task<List<IOElement>> ListFiles(string absoluteDirectoryName)
        {
            checkConnected();

            IsIdled = false;

            if (_dataChannelSocket == null)
                if (EnterPassiveModeAutomatic)
                    await EnterPassiveMode();

            string answer;
            if (!TrySendCommandReadAnswer("LIST " + absoluteDirectoryName, out answer))
            {
                return null;
            }

            if (answer == null)
                return null;

            string passiveAnswer = string.Empty;

            try
            {
                passiveAnswer = ReadAnswer(ClientType.PassiveClient, false, false).Trim();
            }
            catch (IOException) { throw; }

            //dispose passive objects
            _dataChannelSocket.Dispose();
            _dataChannelSocket = null;
            _dataChannelSocketReader = null;
            _dataChannelSocketWriter = null;
            _dataChannelSocketTlsProtocolHandler = null;

            IsIdled = true;

            if (answer.Contains("226") == false)
            {
                try
                {
                    answer = ReadAnswer(ClientType.ActiveClient);
                }
                catch (IOException) { throw; }
            }

            List<IOElement> files = new List<IOElement>();

            if (passiveAnswer.Length == 0)
                return files;

            //detect os for file listing parsing
            int os = 0;
            string[] osHelper = passiveAnswer.Split('\n');

            if (osHelper.Length > 0)
            {
                os = (osHelper[0][10] == ' ' && osHelper[0][9] != ' ') ? 0 : 1;
            }

            //set absoluteDirectoryName to CurrentWorkingDirectory if it is not specified
            if (absoluteDirectoryName == string.Empty)
                absoluteDirectoryName = CurrentWorkingDirectory;

            files = ((_parentClient.OS & (OSType)os) == OSType.Windows) ? await IOElement.ParseWindowsFiles(passiveAnswer, absoluteDirectoryName) : await IOElement.ParseLinuxFiles(passiveAnswer, absoluteDirectoryName);

            files.Sort();
            return files;
        }

        public bool UseUTF8()
        {
            if (_parentClient.SupportedCommands.Contains("UTF8"))
            {
                string answer;
                if (!TrySendCommandReadAnswer("OPTS UTF8 ON", out answer))
                {
                    return false;
                }

                if (ConnectionType == 200)
                    return true;
            }
            return false;
        }
        /// <summary>
        /// Enters the binary mode for passive communication
        /// </summary>
        /// <returns></returns>
        public bool EnterBinaryMode()
        {
            checkConnected();

            for (int i = 0; i < 2; i++)
            {
                string answer;
                if (!TrySendCommandReadAnswer("TYPE I", out answer))
                {
                    return false;
                }

                if (ConnectionType == 200)
                    return true;
                else if (ConnectionType == 421)
                    Login();
            }

            return false;
        }

        /// <summary>
        /// Enters the ASCII mode for passive communication.
        /// </summary>
        /// <returns></returns>
        public bool EnterASCIIMode()
        {
            checkConnected();
            string answer;
            if (!TrySendCommandReadAnswer("TYPE A", out answer))
            {
                return false;
            }

            return (ConnectionType == 227);
        }

        #region Download
        /// <summary>
        /// Downloads a file.
        /// </summary>
        /// <param name="name">The name of the file.</param>
        /// <param name="bytesReadDelegate">A <see cref="FileDownloadBytesReadDelegate"/> which is called everytime an array of bytes has been read from the server. /></param>
        /// <param name="downloadFinished">A <see cref="FileDownloadFinished"/> which is called after the entire download has been completed.</param>
        /// <param name="taskCanceled">A <see cref="IOTaskIsCanceledDelegate"/> which is called before each reading cycle to cancel the download.</param>
        /// <param name="binaryMode">Indicates whether the file should be downloaded in binary or text mode.</param>
        public async void BeginDownloadFile(string name, FileDownloadBytesReadDelegate bytesReadDelegate, FileDownloadFinished downloadFinished, IOTaskIsCanceledDelegate taskCanceled, bool binaryMode = false)
        {
            IsIdled = false;

            checkConnected();

            if (binaryMode)
                EnterBinaryMode();

            if (_dataChannelSocket == null)
                if (EnterPassiveModeAutomatic)
                    await EnterPassiveMode();


            string answer;
            if (!TrySendCommandReadAnswer("RETR " + name, out answer))
            {
                return;
            }

            if (answer == null)
                return;

            if (answer.Trim().StartsWith("425"))
            {
                _dataChannelSocket = null;
                if (EnterPassiveModeAutomatic)
                {
                    await EnterPassiveMode();

                    if (!TrySendCommandReadAnswer("RETR " + name, out answer))
                    {
                        return;
                    }

                    if (answer == null)
                        return;
                }
            }

            if (answer.Trim().StartsWith("150") | answer.Trim().StartsWith("125"))
            {
                beginDownloadData(bytesReadDelegate, new FileDownloadFinished((ulong readbytes) =>
                {
                    EnterASCIIMode();
                    IsIdled = true;
                    downloadFinished(readbytes);
                }), taskCanceled);
            }
        }

        /// <summary>
        /// Internal method to download the content of the download's client connection.
        /// </summary>
        /// <param name="bytesReadDelegate">A <see cref="FileDownloadBytesReadDelegate"/> which is called everytime an array of bytes has been read from the server. /></param>
        /// <param name="downloadFinished">A <see cref="FileDownloadFinished"/> which is called after the entire download has been completed.</param>
        /// <param name="taskCanceled">A <see cref="IOTaskIsCanceledDelegate"/> which is called before each reading cycle to cancel the download.</param>>
        private void beginDownloadData(FileDownloadBytesReadDelegate bytesReadDelegate, FileDownloadFinished downloadFinished, IOTaskIsCanceledDelegate taskCanceled)
        {
            ulong totalReadBytes = 0;
            int readbytes = 1;
            byte[] buffer = new byte[10240];

            while (readbytes > 0)
            {
                if (taskCanceled())
                    break;
                try
                {
                    readbytes = _dataChannelSocketReader.Read(buffer, 0, 1024);
                }
                catch (Exception) { break; }
                finally
                {
                    totalReadBytes += (ulong)readbytes;
                    bytesReadDelegate(readbytes, totalReadBytes, buffer);
                }
            }

            _dataChannelSocket.Dispose();
            _dataChannelSocket = null;

            string answer = string.Empty;

            try
            {
                answer = ReadAnswer(ClientType.ActiveClient);
            }
            catch (IOException) { throw; }

            downloadFinished(totalReadBytes);
        }
        #endregion

        #region Upload
        public async Task<bool> BeginUploadFile(string name, FileUploadReadInputBytesDelegate readInputDelegate, FileUploadBytesWrittenDelegate bytesWrittenDelegate, FileUploadFinishedDelegate uploadFinishedDelegate, IOTaskIsCanceledDelegate taskCanceled, bool binaryMode = false)
        {
            //check parameter to be null
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException("readInputDelegate");
            if (readInputDelegate == null)
                throw new ArgumentNullException("readInputDelegate");
            if (bytesWrittenDelegate == null)
                throw new ArgumentNullException("bytesWrittenDelegate");
            if (uploadFinishedDelegate == null)
                throw new ArgumentNullException("uploadFinishedDelegate");
            if (taskCanceled == null)
                throw new ArgumentNullException("taskCanceled");

            IsIdled = false;

            checkConnected();

            if (_dataChannelSocket == null)
                if (EnterPassiveModeAutomatic)
                    await EnterPassiveMode();

            if (binaryMode)
                EnterBinaryMode();

            string answer;
            if (!TrySendCommandReadAnswer("STOR " + name, out answer))
            {
                return false;
            }

            if (answer == null)
                return false;

            if (answer.Trim().StartsWith("425"))
            {
                _dataChannelSocket = null;
                if (EnterPassiveModeAutomatic)
                {
                    await EnterPassiveMode();

                    if (!TrySendCommandReadAnswer("STOR " + name, out answer))
                    {
                        return false;
                    }

                    if (answer == null)
                        return false;
                }
            }

            if (answer.Trim().StartsWith("150") | answer.Trim().StartsWith("125"))
            {
                beginUploadData(readInputDelegate, bytesWrittenDelegate, new FileUploadFinishedDelegate((bool success) =>
                {
                    try
                    {
                        answer = ReadAnswer(ClientType.ActiveClient);
                    }
                    catch (IOException) { throw; }
                    EnterASCIIMode();
                    IsIdled = true;
                    uploadFinishedDelegate(success && answer.Trim().StartsWith("226"));
                }), taskCanceled);
            }

            return false;
        }

        public async void BeginUploadFileWithUniqueName(FileUploadReadInputBytesDelegate readInputDelegate, FileUploadBytesWrittenDelegate bytesWrittenDelegate, FileUploadFinishedDelegate uploadFinishedDelegate, IOTaskIsCanceledDelegate taskCanceled, bool binaryMode = false)
        {
            //check parameter to be null
            if (readInputDelegate == null)
                throw new ArgumentNullException("readInputDelegate");
            if (bytesWrittenDelegate == null)
                throw new ArgumentNullException("bytesWrittenDelegate");
            if (uploadFinishedDelegate == null)
                throw new ArgumentNullException("uploadFinishedDelegate");
            if (taskCanceled == null)
                throw new ArgumentNullException("taskCanceled");

            IsIdled = false;

            checkConnected();

            //check whether the passive client is already connected. If not connect a new one.
            if (_dataChannelSocket == null)
                if (EnterPassiveModeAutomatic)
                    await EnterPassiveMode();

            //enter the binary mode when requested
            if (binaryMode)
                EnterBinaryMode();

            string answer;
            if (!TrySendCommandReadAnswer("STOU", out answer))
            {
                return;
            }

            if (answer == null)
                return;

            if (answer.Trim().StartsWith("425"))
            {
                _dataChannelSocket = null;
                if (EnterPassiveModeAutomatic)
                {
                    await EnterPassiveMode();

                    if (!TrySendCommandReadAnswer("STOU", out answer))
                    {
                        return;
                    }

                    if (answer == null)
                        return;
                }
            }

            if (answer.Trim().StartsWith("150") & answer.Trim().StartsWith("125"))
            {
                beginUploadData(readInputDelegate, bytesWrittenDelegate, new FileUploadFinishedDelegate((bool success) =>
                {
                    try
                    {
                        answer = ReadAnswer(ClientType.ActiveClient);
                    }
                    catch (IOException) { throw; }
                    EnterASCIIMode();
                    IsIdled = true;
                    uploadFinishedDelegate(success && answer.Trim().StartsWith("226"));
                }), taskCanceled);
            }
        }

        private void beginUploadData(FileUploadReadInputBytesDelegate readInputDelegate, FileUploadBytesWrittenDelegate bytesWrittenDelegate, FileUploadFinishedDelegate uploadFinishedDelegate, IOTaskIsCanceledDelegate taskCanceled)
        {
            ulong totalWrittenBytes = 0;

            byte[] buffer;

            try
            {
                buffer = readInputDelegate(1024);

                while (buffer.Length != 0)
                {
                    //break the loop when the task is marked as canceled
                    if (taskCanceled())
                        break;

                    _dataChannelSocketWriter.Write(buffer);
                    _dataChannelSocketWriter.Flush();
                    totalWrittenBytes += (ulong)buffer.Length;
                    bytesWrittenDelegate(totalWrittenBytes);

                    //read new bytes from the input to send them to the server in the next iteration
                    buffer = readInputDelegate(1024);
                }

                //dispose client to close connection
                _dataChannelSocket.Dispose();
                _dataChannelSocket = null;

                //inform the caller that the upload is finished
                uploadFinishedDelegate(true);
            }
            catch (Exception)
            {
                //if client is not null close and dispose it as well
                if (_dataChannelSocket != null)
                {
                    _dataChannelSocket.Dispose();
                    _dataChannelSocket = null;
                }

                //inform the caller about the failure of the upload
                uploadFinishedDelegate(false);
            }
        }
        #endregion

        #region Helper Methods
        public bool IsNumeric(string input)
        {
            int helper;
            return int.TryParse(input, out helper);
        }
        private async Task<bool> ConnectClient(HostName address, string port, StreamSocket client)
        {
            try
            {
                await client.ConnectAsync(address, port);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool SendCommand(string command)
        {
            var client = _controlChannelSocket;
            var writer = _controlChannelSocketWriter;

            if (client == null)
            {
                IsDisconnected = true;
                if (DisconnectedEvent != null)
                    DisconnectedEvent();
                return false;
            }

            command = command.Trim() + "\n";

            checkConnected();

            try
            {
                writer.Write(_encoding.GetBytes(command));
                writer.Flush();
            }
            catch (Exception)
            {
                //connection was closed
                //throw exception to inform the caller that this call was not successfull
                throw new ConnectionClosedException();
            }


            if (command.ToLower().StartsWith("pass "))
                command = "PASS **********\n";
            if (CommandSendEvent != null)
                CommandSendEvent(command);

            return true;
        }

        public string ReadAnswer(ClientType clientType, bool waitForStatusCode = true, bool printOutput = true)
        {
            var client = (clientType == ClientType.ActiveClient) ? _controlChannelSocket : _dataChannelSocket;
            var reader = (clientType == ClientType.ActiveClient) ? _controlChannelSocketReader : _dataChannelSocketReader;

            string answer = string.Empty;
            byte[] buffer = new byte[1024];
            int readBytes = buffer.Length;

            bool forceToRead = false;

            int status;

            if (waitForStatusCode)
                forceToRead = true;

            while (readBytes == buffer.Length || forceToRead)
            {
                try
                {
                    readBytes = 0;
                    readBytes = reader.Read(buffer, 0, 1024);

                    //no bytes read => cancel the reading process?
                    if (readBytes == 0)
                    {
                        break;
                    }
                }
                catch (IOException) { throw; }
                catch (Exception) { break; }
                finally
                {
                    var newAnswer = _encoding.GetString(buffer, 0, readBytes);
                    var newLines = newAnswer.Split("\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);

                    //the last line of a message looks like this
                    //000 Text\n
                    //detect such a pattern here; if it is found, then the awaitedStatusEndCode has been readed and we don't have to wait for more lines
                    if (waitForStatusCode && newLines.Length > 0 && int.TryParse(newLines.Last().Substring(0, 3), out status) && char.IsWhiteSpace(newLines.Last()[3]) && (newLines.Last().Last() == '\n' || newLines.Last().Last() == '\r'))
                    {
                        forceToRead = false;
                    }

                    answer += newAnswer;
                }
            }

            //get the connection type and set it
            int type;
            Int32.TryParse(answer.Substring(0, 3), out type);
            if (type != 0)
                ConnectionType = type;

            //print the read output
            if (printOutput)
            {
                string[] answers = answer.Split('\n');
                foreach (string item in answers)
                {
                    if (item.Trim().Length > 1)
                        if (AnswerReadEvent != null)
                            AnswerReadEvent(item);
                }
            }

            return answer;
        }

        public bool TrySendCommandReadAnswer(string command, out string result)
        {
            try
            {
                result = SendCommandReadAnswer(command);
                return true;
            }
            catch (IOException)
            {
                result = null;
                return false;
            }
        }

        public string SendCommandReadAnswer(string command)
        {
            for (int i = 0; i < 2; i++)
            {
                try
                {
                    SendCommand(command);
                }
                catch (ConnectionClosedException)
                {
                    IsDisconnected = true;
                    if (DisconnectedEvent != null)
                        DisconnectedEvent();
                    return null;
                }

                try
                {
                    string res = ReadAnswer(ClientType.ActiveClient);
                    if (ConnectionType != 421)
                        return res;
                }
                catch (IOException) { throw; }
            }

            return string.Empty;
        }
        #endregion
        #endregion
    }
}
